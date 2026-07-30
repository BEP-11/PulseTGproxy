package stats

import (
	"fmt"
	"math"
	"strconv"
	"sync"
	"time"
)

type ConnectionInfo struct {
	ID        string
	ProxyID   string
	Key       string
	ClientIP  string
	UserAgent string
	Start     time.Time
	BytesIn   int64
	BytesOut  int64
	Transport string
	Padded    bool
	Active    bool
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
	Timestamp      time.Time
	Uptime         time.Duration
	ProxiesCount   int
	ConnsActive    int
	BytesInTotal   int64
	BytesOutTotal  int64
	ConnsTotal     int64
	Proxies        []ProxyStats
	ErrorsCount    int64
	PaddedRequests int64
}

type Tracker struct {
	mu         sync.RWMutex
	startTime  time.Time
	conns      map[string]*ConnectionInfo
	proxyKeys  map[string]string
	proxies    map[string]*ProxyStats
	totalIn    int64
	totalOut   int64
	totalConns int64
	paddedReqs int64
	errors     int64
}

func NewTracker() *Tracker {
	return &Tracker{
		startTime: time.Now(),
		conns:     make(map[string]*ConnectionInfo),
		proxyKeys: make(map[string]string),
		proxies:   make(map[string]*ProxyStats),
	}
}

func (t *Tracker) RegisterProxy(id, label, key string, limit int64, enabled bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := key[:minInt(len(key), 8)]
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
	if ps, ok := t.proxies[info.ProxyID]; ok {
		ps.ConnsActive++
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
		if ps, ok := t.proxies[conn.ProxyID]; ok {
			ps.BytesInTotal += inBytes
			ps.BytesOutTotal += outBytes
			limitMB := ps.LimitMB
			if limitMB > 0 {
				totalMB := (ps.BytesInTotal + ps.BytesOutTotal) >> 20
				ps.BandwidthUsedPct = float64(totalMB) / float64(limitMB) * 100
				if ps.BandwidthUsedPct > 100 {
					ps.BandwidthUsedPct = 100
				}
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
		if ps, ok := t.proxies[conn.ProxyID]; ok {
			ps.ConnsActive--
			ps.ConnsTotal++
		}
		delete(t.conns, connID)
	}
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
func (t *Tracker) GetProxyStats(key string) *ProxyStats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Find proxy by key preview match
	for _, ps := range t.proxies {
		if strings.HasPrefix(ps.KeyPreview, key[:minInt(len(key), len(ps.KeyPreview))]) {
			return ps
		}
	}
	return nil

func (t *Tracker) GetGlobal() GlobalStats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var proxyList []ProxyStats
	for _, ps := range t.proxies {
		proxyList = append(proxyList, *ps)
	}
	return GlobalStats{
		Timestamp:      time.Now(),
		Uptime:         time.Since(t.startTime),
		ProxiesCount:   len(t.proxies),
		ConnsActive:    len(t.conns),
		BytesInTotal:   t.totalIn,
		BytesOutTotal:  t.totalOut,
		ConnsTotal:     t.totalConns,
		Proxies:        proxyList,
		ErrorsCount:    t.errors,
		PaddedRequests: t.paddedReqs,
	}
}

func ByteSize(b int64) string {
	if b < 1024 {
		return strconv.FormatInt(b, 10) + " B"
	}
	sizes := []string{"KiB", "MiB", "GiB", "TiB"}
	val := float64(b)
	for i, size := range sizes {
		if val < 1024 || i == len(sizes)-1 {
			return fmt.Sprintf("%.1f %s", math.Max(math.Floor(val*10)/10, 0.1), size)
		}
		val /= 1024
	}
	return "0 B"
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
