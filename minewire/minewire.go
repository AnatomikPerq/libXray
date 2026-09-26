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
// Each engine exposes a local SOCKS5 listener; Xray dials it as an ordinary
// socks outbound. Several engines can run at once, keyed by that local port:
// a balancer may hold more than one minewire node, and a node switch starts
// the new engine before the old one is stopped.
package minewire

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/dmitrymodder/minewire-cli/src/core"
)

var (
	mu      sync.Mutex
	engines = map[int]*core.Engine{}
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
	// LocalPort is optional. Zero means "pick a free one". An engine already
	// on that port is replaced.
	LocalPort int
}

// Start brings one tunnel up and returns its local SOCKS5 port.
func Start(options StartOptions) (int, error) {
	if options.ServerAddress == "" || options.Password == "" {
		return 0, errors.New("minewire: server address and password are required")
	}

	mu.Lock()
	defer mu.Unlock()

	port := options.LocalPort
	if port <= 0 {
		free, err := freePort()
		if err != nil {
			return 0, err
		}
		port = free
	} else if previous, ok := engines[port]; ok {
		previous.Stop()
		delete(engines, port)
	}

	mode := options.Mode
	if mode != core.ModeRealistic {
		mode = core.ModeFast
	}

	cfg := core.Config{
		// Loopback only: the listener has no authentication of its own.
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
	engines[port] = next
	return port, nil
}

// Stop tears down the engine on localPort, or every engine for 0. Stopping
// an engine that is not running is fine.
func Stop(localPort int) error {
	mu.Lock()
	defer mu.Unlock()
	var result error
	for port, engine := range engines {
		if localPort != 0 && port != localPort {
			continue
		}
		if err := engine.Stop(); err != nil && result == nil {
			result = err
		}
		delete(engines, port)
	}
	return result
}

// EngineState reports one engine.
type EngineState struct {
	LocalPort int
	Running   bool
	Connected bool
	LastError string
}

// State reports every running engine.
func State() []EngineState {
	mu.Lock()
	defer mu.Unlock()
	states := make([]EngineState, 0, len(engines))
	for port, engine := range engines {
		status := engine.Status()
		states = append(states, EngineState{
			LocalPort: port,
			Running:   status.Running,
			Connected: status.Connected,
			LastError: status.LastError,
		})
	}
	return states
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
