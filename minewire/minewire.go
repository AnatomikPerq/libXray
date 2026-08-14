// Package minewire embeds the minewire tunnel engine into libXray.
//
// minewire (MIT, github.com/dmitrymodder/minewire-cli) masquerades traffic as
// the Minecraft protocol. Its src/core is a plain Go library, and libXray is
// Go as well, so the engine runs inside the very same shared library the app
// already loads instead of a separate executable.
//
// That matters for more than tidiness: Android and iOS cannot spawn a
// bundled executable at all, so a sidecar process has no path to mobile.
// Running in-process also keeps the password in memory instead of writing it
// to a config file on disk.
//
// The engine still exposes a local SOCKS5 listener; Xray dials it as an
// ordinary socks outbound. Only the process boundary is gone.
package minewire

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/dmitrymodder/minewire-cli/src/core"
)

var (
	mu     sync.Mutex
	engine *core.Engine
	local  string
)

// StartOptions describes one minewire node.
type StartOptions struct {
	// ServerAddress is host:port of the minewire server. Callers should pass
	// an already resolved address: once the tunnel is up, DNS may itself
	// depend on the tunnel that is not working yet.
	ServerAddress string
	Password      string
	// Mode is "fast" or "realistic" and has to match the server.
	Mode string
	// LocalPort is optional. Zero means "pick a free one".
	LocalPort int
}

// Start brings the tunnel up and returns the local SOCKS5 port.
//
// Any previous engine is stopped first: node parameters may have changed, and
// restarting is cheaper to reason about than diffing configs.
func Start(options StartOptions) (int, error) {
	if options.ServerAddress == "" || options.Password == "" {
		return 0, errors.New("minewire: server address and password are required")
	}

	mu.Lock()
	defer mu.Unlock()
	stopLocked()

	port := options.LocalPort
	if port <= 0 {
		free, err := freePort()
		if err != nil {
			return 0, err
		}
		port = free
	}

	mode := options.Mode
	if mode != core.ModeRealistic {
		mode = core.ModeFast
	}

	cfg := core.Config{
		LocalPort:     fmt.Sprintf("127.0.0.1:%d", port),
		ServerAddress: options.ServerAddress,
		Password:      options.Password,
		// Xray talks to the engine over SOCKS5; the HTTP CONNECT mode would
		// not carry anything but TCP either way.
		ProxyType: "socks5",
		Mode:      mode,
	}

	next := core.NewEngine(cfg, core.NewLogger(core.LevelWarn))
	if err := next.Start(); err != nil {
		return 0, err
	}
	engine = next
	local = cfg.LocalPort
	return port, nil
}

// Stop tears the tunnel down. Stopping an already stopped engine is fine.
func Stop() error {
	mu.Lock()
	defer mu.Unlock()
	return stopLocked()
}

func stopLocked() error {
	if engine == nil {
		return nil
	}
	err := engine.Stop()
	engine = nil
	local = ""
	return err
}

// State reports whether the tunnel is up and where it listens.
func State() (running bool, connected bool, localAddr string, lastError string) {
	mu.Lock()
	defer mu.Unlock()
	if engine == nil {
		return false, false, "", ""
	}
	status := engine.Status()
	return status.Running, status.Connected, local, status.LastError
}

// freePort asks the OS for an unused loopback port and releases it again.
//
// The window between releasing and binding is a theoretical race, but the
// alternative is a fixed port, which is occupied far more often than not.
func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0, errors.New("minewire: unexpected listener address")
	}
	return addr.Port, nil
}
