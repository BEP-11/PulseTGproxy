package fake

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"time"
)

// DPI patterns that we emulate to avoid detection
var (
	patterns = []struct {
		name    string
		header  []byte
		payload func(n int) []byte
	}{
		{
			name: "tls-hello",
			header: []byte{0x16, 0x03, 0x03}, // TLS record type, version
			payload: func(n int) []byte {
				b := make([]byte, n*3/4)
				rand.Read(b)
				// Make it look like handshake
				if len(b) > 5 {
					b[0] = byte(n%256) // Content type
					binary.BigEndian.PutUint16(b[1:3], uint16(len(b)-5)+5)
				}
				return b
			},
		},
		{
			name: "quic",
			header: []byte{0x83, 0xe9}, // QUIC magic bytes hint
			payload: func(n int) []byte {
				b := make([]byte, n)
				rand.Read(b)
				return b
			},
		},
	}

	// Common HTTPS port patterns
	hports = []int{443, 8443, 2053, 10001, 10002}

	defaultUserAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
		"Mozilla/5.0 (Linux; Android 14) Mobile Chrome/120.0.0.0 Safari/537.36",
	}
)

// PaddingMode defines the padding strategy
type PaddingMode string

const (
	PaddingRandom  PaddingMode = "random"
	PaddingZipf    PaddingMode = "zipf"
	PaddingUniform PaddingMode = "uniform"
)

// Engine performs anti-DPI padding and obfuscation
type Engine struct {
	enabled         bool
	pattern         PaddingMode
	minBytes        int
	maxBytes        int
	rate            float64 // 0-1 probability of padding
	userAgents      []string
	fakeSNI         []string
	randomHeaders   bool
	requestCounter  uint64
}

// Config for the anti-DPI engine
type Config struct {
	Enabled       bool
	Pattern       PaddingMode
	MinBytes      int
	MaxBytes      int
	Rate          float64
	UserAgents    []string
	FakeSNI       []string
	RandomHeaders bool
}

func NewEngine(cfg Config) *Engine {
	if cfg.Pattern == "" {
		cfg.Pattern = PaddingRandom
	}
	if cfg.UserAgents == nil {
		cfg.UserAgents = defaultUserAgents
	}
	return &Engine{
		enabled:       cfg.Enabled,
		pattern:       cfg.Pattern,
		minBytes:      cfg.MinBytes,
		maxBytes:      cfg.MaxBytes,
		rate:          cfg.Rate,
		userAgents:    cfg.UserAgents,
		fakeSNI:       cfg.FakeSNI,
		randomHeaders: cfg.RandomHeaders,
	}
}

// ShouldPad determines if this request should be padded based on rate
func (e *Engine) ShouldPad() bool {
	if !e.enabled {
		return false
	}
	return true // Always pad when enabled
}

// PaddedLength returns the size of padding to add
func (e *Engine) PaddedLength() int {
	switch e.pattern {
	case PaddingZipf:
		// Zipf-like distribution: mostly small, occasionally very large
		r := float64(e.minBytes + randIntn(e.maxBytes-e.minBytes))
		return int(math.Pow(r, 0.5)) * (e.maxBytes - e.minBytes) / int(math.Sqrt(float64(e.maxBytes))) + e.minBytes
	case PaddingUniform:
		return e.minBytes + randIntn(e.maxBytes-e.minBytes+1)
	default: // random
		// Mix of small and large like real HTTPS
		if randFloat() < 0.7 {
			return int(randFloat()*float64(200)) + 50 // Small request
		}
		return e.minBytes + randIntn((e.maxBytes-e.minBytes)/2)
	}
}

// GeneratePadding creates realistic padding data
func (e *Engine) GeneratePadding(size int) []byte {
	pat := patterns[randIntn(len(patterns))]
	payload := pat.payload(size)
	return append(pat.header, payload...)
}

// BuildFakeResponse builds a fake HTTP response for padding CONNECT requests
func (e *Engine) BuildFakeResponse(connID string) []byte {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "HTTP/1.1 200 OK\r\n")
	fmt.Fprintf(buf, "Server: cloudflare\r\n")
	fmt.Fprintf(buf, "Date: %s\r\n", time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))

	if e.randomHeaders && len(e.userAgents) > 0 {
		ua := e.userAgents[randIntn(len(e.userAgents))]
		fmt.Fprintf(buf, "User-Agent: %s\r\n", ua)
	}

	// Add random padding data after headers
	padSize := e.PaddedLength()
	buf.WriteString("\r\n")
	padding := e.GeneratePadding(padSize)
	buf.Write(padding)

	return buf.Bytes()
}

// ObfuscateTransport handles transparent inline TCP obfuscation
func ObfuscateTransport(srcReader *bufio.Reader, dstWriter net.Conn, cfg Config) (int64, error) {
	var totalWritten int64

	// Read MTProto packet length prefix (32-bit little-endian)
	lengthBytes := make([]byte, 4)
	n, err := srcReader.Read(lengthBytes)
	if err != nil || n < 4 {
		return totalWritten, err
	}

	pktLen := binary.LittleEndian.Uint32(lengthBytes)
	if pktLen > 512*1024+4 { // Max packet 516KiB + 4 prefix
		return totalWritten, fmt.Errorf("packet too large: %d", pktLen)
	}

	pktData := make([]byte, int(pktLen))
	n, err = srcReader.Read(pktData)
	if err != nil {
		return totalWritten, err
	}

	totalRead := int64(n + 4)

	// Add padding if enabled
	if cfg.Enabled && randFloat() < cfg.Rate {
		padLen := cfg.MinBytes + randIntn(cfg.MaxBytes-cfg.MinBytes+1)
		padding := make([]byte, padLen)
		rand.Read(padding)
		// Write original packet + padding as one block
		_, err = dstWriter.Write(append(lengthBytes, pktData...))
		if err != nil {
			return totalWritten, err
		}
		totalWritten += int64(len(lengthBytes) + n)

		// Separate padding frame (looks like new request/response to DPI)
		time.Sleep(time.Microsecond * time.Duration(randIntn(200)))
		_, err = dstWriter.Write(padding)
		if err != nil {
			return totalWritten, err
		}
		totalWritten += int64(padLen)
		return totalRead + int64(padLen), nil
	}

	_, err = dstWriter.Write(append(lengthBytes, pktData...))
	if err != nil {
		return totalWritten, err
	}
	totalWritten += int64(len(lengthBytes) + n)
	return totalRead, totalWritten
}

// GenerateProxyLink creates a tg://proxy link
func GenerateProxyLink(key, domain string, port int) string {
	return fmt.Sprintf("tg://proxy?server=%s&port=%d&secret=%s", domain, port, key)
}

// GenerateQRCodeData returns the data for QR code generation
func GenerateQRCodeData(link string) string {
	return link
}

func randIntn(n int) int {
	if n <= 0 {
		return 0
	}
	b := make([]byte, 4)
	rand.Read(b)
	return int(binary.LittleEndian.Uint32(b)) % n
}

func randFloat() float64 {
	b := make([]byte, 8)
	rand.Read(b)
	u := binary.LittleEndian.Uint64(b)
	return float64(u&0x1fffffffffffff) / (1 << 53)
}
