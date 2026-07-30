package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ProxyInstance represents a single Telegram MTProxy instance with its own API key
type ProxyInstance struct {
	ID       string `yaml:"id"`
	Key      string `yaml:"key"`        // 32-byte hex API key for TMProxy Host header
	Port     int    `yaml:"port"`       // Internal port mapped by nginx
	Limit    int64  `yaml:"limit_mb"`   // Traffic limit in MB (0 = unlimited)
	Enabled  bool   `yaml:"enabled"`
	Label    string `yaml:"label"`      // Human-readable label
	GeoHint  string `yaml:"geo_hint"`   // Geographic hint for client routing
}

// TransportConfig defines the transport protocol settings
type TransportConfig struct {
	HTTP      *TransportHTTP       `yaml:"http,omitempty"`
	WebSocket *TransportWS       `yaml:"websocket,omitempty"`
	Grpc      *TransportGrpc     `yaml:"grpc,omitempty"`
	TLS       *TransportTLS      `yaml:"tls,omitempty"`
}



type TransportHTTP struct {
	Enabled         bool `yaml:"enabled"`
	Port            int  `yaml:"port"`
	RequestTimeout  int  `yaml:"request_timeout_sec"`
	ReadBufferSize  int  `yaml:"read_buffer_kb"`
	WriteBufferSize int  `yaml:"write_buffer_kb"`
}

type TransportWS struct {
	Enabled         bool   `yaml:"enabled"`
	Path            string `yaml:"path"`
	Compression     bool   `yaml:"compression"`
	HandshakeTimeout int  `yaml:"handshake_timeout_sec"`
}

type TransportGrpc struct {
	Enabled           bool   `yaml:"enabled"`
	ServiceName       string `yaml:"service_name"`
	Method            string `yaml:"method"`
	MaxRecvMsgSizeKB  int    `yaml:"max_recv_msg_size_kb"`
}

type TransportTLS struct {
	Enabled   bool   `yaml:"enabled"`
	CertFile  string `yaml:"cert_file"`
	KeyFile   string `yaml:"key_file"`
	SNI       string `yaml:"sni"`
	FakeSNI   []string `yaml:"fake_sni"` // Random SNI values for DPI bypass
}

// AntiCensorshipConfig holds anti-DPI and anti-censorship settings
type AntiCensorshipConfig struct {
	Enabled    bool  `yaml:"enabled"`
	Padding    *PaddingConfig `yaml:"padding"`
	Obfuscation *ObfuscationConfig `yaml:"obfuscation"`
}

type PaddingConfig struct {
	MinBytes   int `yaml:"min_bytes"`
	MaxBytes   int `yaml:"max_bytes"`
	Rate       float64 `yaml:"rate"` // Percentage of padded requests (0-1)
	Pattern    string `yaml:"pattern"` // "random", "zipf", "uniform"
}

type ObfuscationConfig struct {
	RandomHeaders     bool               `yaml:"random_headers"`
	CustomContentType  string           `yaml:"custom_content_type"`
	FakeAcceptEncoding []string         `yaml:"fake_accept_encoding"`
	VaryHeader        bool             `yaml:"vary_header"`
	UserAgents        []string         `yaml:"user_agents"`
}

// MonitorConfig for stats and web dashboard
type MonitorConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Port       int    `yaml:"port"`
	Path       string `yaml:"path"` // e.g. /stats
	AuthUser   string `yaml:"auth_user"`
	AuthPass   string `yaml:"auth_pass"`
	RefreshSec int    `yaml:"refresh_sec"`
}

// Config is the main application configuration
type Config struct {
	Version          string                `yaml:"version"`
	ListenHost       string                `yaml:"listen_host"`
	ListenPort       int                   `yaml:"listen_port"`
	MaxConnections   int                   `yaml:"max_connections"`
	LogLevel         string                `yaml:"log_level"`
	LogFile          string                `yaml:"log_file"`
	Proxies          []ProxyInstance       `yaml:"proxies"`
	Transport        *TransportConfig      `yaml:"transport"`
	AntiCensorship   *AntiCensorshipConfig `yaml:"anti_censorship"`
	Monitor          *MonitorConfig        `yaml:"monitor"`
	Nginx            *NginxConfig          `yaml:"nginx"`
}

// NginxConfig stores nginx reverse proxy settings
type NginxConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Path       string `yaml:"conf_path"`
	Generate   bool   `yaml:"auto_generate"`
	PublicIP   string `yaml:"public_ip"`
	CertFile   string `yaml:"cert_file"` // Let's encrypt cert
	KeyFile    string `yaml:"key_file"`
}

// Load reads configuration from file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	cfg.ListenPort = 8080
	cfg.ListenHost = "127.0.0.1"
	cfg.MaxConnections = 64000
	cfg.LogLevel = "info"
	cfg.Transport = &TransportConfig{
		HTTP:        &TransportHTTP{Enabled: true, Port: 8080},
		WebSocket:   &TransportWS{Enabled: false, Path: "/ws"},
		Grpc:        &TransportGrpc{Enabled: false, ServiceName: "mtproxy", Method: "Connect"},
		TLS:         &TransportTLS{Enabled: false, FakeSNI: []string{"google.com", "facebook.com", "cloudflare.com"}},
	}
	cfg.AntiCensorship = &AntiCensorshipConfig{
		Enabled: true,
		Padding: &PaddingConfig{MinBytes: 4096, MaxBytes: 65327, Rate: 1.0, Pattern: "random"},
		Obfuscation: &ObfuscationConfig{
			RandomHeaders:     true,
			CustomContentType: "",
			FakeAcceptEncoding: []string{"identity"},
			VaryHeader:        true,
			UserAgents:        defaultUserAgents,
		},
	}
	cfg.Monitor = &MonitorConfig{Enabled: true, Port: 8081, Path: "/stats", RefreshSec: 5}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Resolve relative paths
	dir := filepath.Dir(path)
	if cfg.LogFile != "" && !filepath.IsAbs(cfg.LogFile) {
		cfg.LogFile = filepath.Join(dir, cfg.LogFile)
	}
	if cfg.Transport.TLS.CertFile != "" && !filepath.IsAbs(cfg.Transport.TLS.CertFile) {
		cfg.Transport.TLS.CertFile = filepath.Join(dir, cfg.Transport.TLS.CertFile)
	}
	if cfg.Transport.TLS.KeyFile != "" && !filepath.IsAbs(cfg.Transport.TLS.KeyFile) {
		cfg.Transport.TLS.KeyFile = filepath.Join(dir, cfg.Transport.TLS.KeyFile)
	}

	return &cfg, nil
}

var defaultUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
}

// Save writes configuration to file
func (cfg *Config) Save(path string) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}
