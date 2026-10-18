package core

import (
	"context"
	"io"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

// Tunnel behavior mode - must match the server's server.yaml `mode` setting
// for the traffic profile to make sense; client and server throttle
// independently, they don't negotiate it over the wire.
const (
	ModeFast      = "fast"
	ModeRealistic = "realistic"
)

// Config is the engine configuration. Field names/tags are shared between
// client.yaml (CLI mode) and the JSON daemon control protocol, so a UI can
// send exactly the same shape it would put in the YAML file.
type Config struct {
	LocalPort     string `yaml:"local_port" json:"local_port"`
	ServerAddress string `yaml:"server_address" json:"server_address"`
	Password      string `yaml:"password" json:"password"`
	ProxyType     string `yaml:"proxy_type" json:"proxy_type"` // "socks5" or "http"

	// Tunnel behavior mode: "fast" (default, unrestricted) or "realistic"
	// (throttled upload to match the server's throttled download).
	Mode string `yaml:"mode" json:"mode"`
	// Sustained upload cap in realistic mode, KB/s (kilobytes, not kilobits).
	RealisticBandwidthKB int `yaml:"realistic_bandwidth_kb" json:"realistic_bandwidth_kb"`
	// Burst allowance in realistic mode, KB.
	RealisticBurstKB int `yaml:"realistic_burst_kb" json:"realistic_burst_kb"`

	// Dial, when set, opens the connection to the server, for example bound
	// to the physical interface while a TUN captures the default route.
	// Not part of the file or IPC config (libXray patch).
	Dial func(ctx context.Context, network, address string) (net.Conn, error) `yaml:"-" json:"-"`

	// LogWriter, when set, receives yamux's own messages (keepalive
	// failures, stream errors), which otherwise go to stderr. A GUI host
	// has no stderr. Not part of the file or IPC config (libXray patch).
	LogWriter io.Writer `yaml:"-" json:"-"`
}

// LoadConfigFile reads and validates a client.yaml-shaped file, applying
// defaults for anything left unset.
func LoadConfigFile(path string) (Config, error) {
	var cfg Config
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, err
	}
	cfg.ApplyDefaults(nil)
	return cfg, nil
}

// ApplyDefaults fills in unset/invalid fields with sane defaults. log may be
// nil (used e.g. before a Logger exists yet); a non-nil log gets a warning
// when a value is corrected.
func (c *Config) ApplyDefaults(log *Logger) {
	switch c.Mode {
	case ModeFast, ModeRealistic:
		// valid, keep as-is
	case "":
		c.Mode = ModeFast
	default:
		if log != nil {
			log.Warnf("unknown mode %q in config, falling back to %q", c.Mode, ModeFast)
		}
		c.Mode = ModeFast
	}
	if c.RealisticBandwidthKB <= 0 {
		c.RealisticBandwidthKB = 40
	}
	if c.RealisticBurstKB <= 0 {
		c.RealisticBurstKB = 512
	}
	if c.ProxyType == "" {
		c.ProxyType = "http"
	}
	if c.LocalPort == "" {
		c.LocalPort = ":1080"
	}
}
