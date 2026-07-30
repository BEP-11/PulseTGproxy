package stats

import (
	"sync"
	"time"
)

type ConnectionInfo struct {
	ID         string
	ProxyID    string
	Key        string
	ClientIP   string
	UserAgent  string
	Start      time.Time
	BytesIn    int64
	BytesOut   int64
	Transport  string // http-connect, websocket, grpc
	Padded     bool
	Active     bool
}

type ProxyStats struct {
	ProxyID          string
	Label            string
	KeyPreview       string
	ConnsTotal       int64
	ConnsActive      int
	BytesInTotal     int64
	BytesOutTotal    int64
	LimitMB          int64
	BandwidthUsedPct float64
	Enabled          bool
}

type GlobalStats struct {
	Timestamp       time.Time
	Uptime          time.Duration
	ProxiesCount    int
	ConnsActive     int
(BytesInTotal      int64
BytesOutTotal    int64
ConnsTotal       int64
Proxies         []ProxyStats
ErrorsCount      int64
PaddedRequests   int64)
}

type Tracker struct {
	mu          sync.RWMutex
	startTime   time.Time
	conns       map[string]*ConnectionInfo
	proxyKeys   map[string]string // key -> proxyID
	proxyConns  map[string]int    // proxyID -> active count
	totalIn     int64
	totalOut    int64
	totalConns  int64
	paddedReqs  int64
	errors      int64
	proxies     map[string]*ProxyStats // proxyID -> stats
}

func NewTracker() *Tracker {
	return &Tracker{
		startTime:   time.Now(),
		conns:       make(map[string]*ConnectionInfo),
		proxyKeys:   make(map[string]string),
		proxyConns:  make(map[string]int),
		proxies:     make(map[string]*ProxyStats),
	}
}

func (t *Tracker) RegisterProxy(id, label, key string, limit int64, enabled bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	k := key[:min(len(key), 8)]
	t.proxies[id] = &ProxyStats{
		ProxyID:     id,
		Label:       label,
		KeyPreview:  k + "...",
		LimitMB:     limit,
		ConnsActive: 0,
		Enabled:     enabled,
	}
	t.proxyKeys[key] = id
}

func (t *Tracker) Track(connID string, info ConnectionInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()

	info.Start = time.Now()
	info.Active = true
	t.conns[connID] = &info
	t.totalConns++
	if _, ok := t.proxies[info.ProxyID]; ok {
		t.proxies[info.ProxyID].ConnsActive++
	}
}

func (t *Tracker) AddTraffic(connID string, inBytes, outBytes int64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if conn := t.conns[connID]; conn != nil {
		conn.BytesIn += inBytes
		conn.BytesOut += outBytes
		t.totalIn += inBytes
		t.totalOut += outBytes
		if ps := t.proxies[conn.ProxyID]; ps != nil {
			ps.BytesInTotal += inBytes
			ps.BytesOutTotal += outBytes
			limitMB := ps.LimitMB
			if limitMB > 0 {
				totalMB := (ps.BytesInTotal + ps.BytesOutTotal) >> 20
				ps.BandwidthUsedPct = float64(totalMB) / float64(limitMB) * 100
			} else {
				ps.BandwidthUsedPct = 0
			}
		}
	}
}

func (t *Tracker) MarkClosed(connID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if conn := t.conns[connID]; conn != nil {
		conn.Active = false
// Update proxy active count
if ps := t.proxies[conn.ProxyID]; ps != nil {
ps.ConnsActive--
ps.ConnsTotal++
}
delete(t.conns, connID) }
}

func (t *Tracker) MarkPadded() {
t.mu.Lock()
defer t.mu.Unlock()
t.paddedReqs++
}

func (t *Tracker) IncError() {
t.mu.Lock()
defer t.mu.Unlock()
t.errors++
}

func (t *Tracker) GetGlobal() GlobalStats {
t.mu.RLock()
defer t.mu.RUnlock()

var proxyList []ProxyStats
for _, ps := range t.proxies {
proxyList = append(proxyList, *ps)
}

return GlobalStats{
Timestamp:    time.Now(),
Uptime:       time.Since(t.startTime),
ProxiesCount: len(t.proxies),
ConnsActive:  len(t.conns),
BytesInTotal: t.totalIn,
BytesOutTotal: t.totalOut,
ConnsTotal:   t.totalConns,
Proxies:      proxyList,
ErrorsCount:  t.errors,
PaddedRequests: t.paddedReqs,
}
}

func (t *Tracker) GetProxyStats(id string) *ProxyStats {
t.mu.RLock()
defer t.mu.RUnlock()
return t.proxies[id]
}

func ByteSize(b int64) string {
const unit = 1024
if b < unit {
return strconv.FormatInt(b, 10) + " B"
}
div, suffix := int64(unit), "KiB"
for range 3 {
next := b / (unit * unit)
if next < 1 {
break
}
div *= unit
suffix = append(suffix[0], []byte("TiPiEiG")[len(suffix)-3])
b = next
}
return bytes.NewBuffer(b/1024, suffix, "%d %.1f %s", b/div, float64(b%div)/float64(div), suffix)
	}

func min(a, b int) int {
if a < b {
return a
}
return b
}
