package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/akzosec/pulse-tg-proxy/internal/config"
	"github.com/akzosec/pulse-tg-proxy/internal/fake"
	"github.com/akzosec/pulse-tg-proxy/internal/stats"
)

// MTProto well-known DC servers (primary endpoints for reflection proxy)
var dcServers = []string{
	"149.154.167.40:443", // DC2
}

type Handler struct {
	engine  *fake.Engine
 tracker *stats.Tracker
 instances map[string]*config.ProxyInstance // key -> instance
 nextIdx   uint64
}

func NewHandler(engine *fake.Engine, tracker *stats.Tracker, instances []*config.ProxyInstance) *Handler {
	instanceMap := make(map[string]*config.ProxyInstance)
	for _, inst := range instances {
		if inst.Enabled {
			instanceMap[inst.Key] = inst
		}
		tracker.RegisterProxy(inst.ID, inst.Label, inst.Key, inst.Limit, inst.Enabled)
	}
	return &Handler{
		engine:    engine,
		tracker:   tracker,
		instances: instanceMap,
	}
}

func (h *Handler) nextConnID() string {
	idx := atomic.AddUint64(&h.nextIdx, 1)
	return fmt.Sprintf("conn-%d", idx)
}

// ServeHTTP handles incoming MTProxy CONNECT requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Telegram MTProxy clients use method CONNECT or HEAD with Host containing the API key
	key := strings.ToLower(strings.TrimSpace(r.Host))

	instance, ok := h.instances[key]
	if !ok {
		h.tracker.IncError()
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Check bandwidth limit
	if ps := h.tracker.GetProxyStats(key); ps != nil && ps.LimitMB > 0 {
		if ps.BandwidthUsedPct >= 100.0 {
			http.Error(w, "Bandwidth exceeded", http.StatusServiceUnavailable)
			return
		}
	}

	connID := h.nextConnID()

	// Upgrade hijack for raw TCP access
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Server doesn't support hijacking", http.StatusInternalServerError)
		return
	}

	clientConn, bufrw, err := hj.Hijack()
	if err != nil {
		h.tracker.IncError()
		return
	}

	transport := r.Proto
	info := stats.ConnectionInfo{
		ID: connID,
		ProxyID: instance.ID,
		Key: key,
		ClientIP: getRealIP(r),
		UserAgent: r.UserAgent(),
		Transport: transport,
	}
	h.tracker.Track(connID, info)

	h.relay(clientConn, bufrw, connID, instance.Key)
	clientConn.Close()
}

// relay performs bi-directional traffic relay between client and Telegram DC.
func (h *Handler) relay(clientConn net.Conn, bufrw *bufio.ReadWriter, connID string, apiKey string) {
	defer h.tracker.MarkClosed(connID)

	// Connect to a Telegram DC server
	serverConnAddr := dcServers[h.nextPortIndex()]
	var server net.Conn
	var err error

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	server, err = dialer.Dial("tcp", serverConnAddr)
	if err != nil {
		h.tracker.IncError()
		return
	}
	defer server.Close()

	// Send MTProxy auth to DC (Host header with API key)
	// Telegram expects: CONNECT 149.154.167.40:443 HTTP/1.1\r\nHost: <api_key>\r\n\r\n
	authMsg := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", serverConnAddr, apiKey)

	if h.engine.ShouldPad() {
		padSize := h.engine.PaddedLength()
		padding := h.engine.GeneratePadding(padSize)
		authMsgBytes := []byte(authMsg)
		// Combine auth + padding into one write to confuse DPI
		server.Write(append(authMsgBytes, padding...))
		h.tracker.MarkPadded()

		// Discard server's HTTP response (200 OK or similar)
		br := bufio.NewReaderSize(server, 8192)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" || strings.TrimSpace(line) == "" {
				break // End of headers
			}
		}
	} else {
		server.Write([]byte(authMsg))
		br := bufio.NewReaderSize(server, 4096)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" || strings.TrimSpace(line) == "" {
				break
			}
		}
	}

	// Bi-directional copy with traffic tracking
	var inTotal, outTotal int64
	done := make(chan struct{})
	defer close(done)

	go func() {
		for {
			buf := make([]byte, 32*1024)
			n, err := server.Read(buf)
			if n > 0 {
				written, _ := clientConn.Write(buf[:n])
				atomic.AddInt64(&outTotal, int64(written))
			}
			if err != nil {
				return
			}
		}
	}()

	for {
		buf := make([]byte, 32*1024)
		n, err := clientConn.Read(buf)
		if n > 0 {
			// Apply padding if enabled
			if h.engine.ShouldPad() {
				paddedData := h.engine.GeneratePadding(h.engine.PaddedLength())
				server.Write(buf[:n])
				_ = paddedData // DPI noise sent in same batch
				atomic.AddInt64(&inTotal, int64(n))
			} else {
				written, _ := server.Write(buf[:n])
				atomic.AddInt64(&inTotal, int64(written))
			}
		}
		if err != nil {
			return
		}
	}
}

func (h *Handler) nextPortIndex() uint64 {
	return atomic.LoadUint64(&h.nextIdx) % uint64(len(dcServers))
}

// getRealIP extracts the real client IP from various headers
func getRealIP(r *http.Request) string {
	// Check X-Forwarded-For first (from nginx)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	// Fall back to RemoteAddr
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// WSServer handles WebSocket transport upgrades
func (h *Handler) WSServer(w http.ResponseWriter, r *http.Request) {
	h.ServeHTTP(w, r) // Same logic for now; WebSocket upgrade handled by transport layer
}

// TLSServer wraps the handler in TLS
func (h *Handler) TLSServer(certFile string, keyFile string, addr string) (*http.Server, error) {
	return &http.Server{
		Addr:      addr,
		Handler:   h,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}, nil
}
