package core

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/hashicorp/yamux"
)

// Version is the core library / CLI version.
const Version = "26.7.3"

// Status is a snapshot of the engine's current state, safe to serialize
// (e.g. to JSON for a UI, or over the daemon IPC protocol).
type Status struct {
	Running       bool   `json:"running"`
	Connected     bool   `json:"connected"`
	Mode          string `json:"mode"`
	ProxyType     string `json:"proxy_type"`
	LocalAddr     string `json:"local_addr"`
	ServerAddress string `json:"server_address"`
	LastError     string `json:"last_error,omitempty"`
}

// Engine is the core tunnel+proxy runtime. It replaces the old package-level
// globals (session, sessionLock, cfg, ...) so a desktop daemon or an Android
// gomobile wrapper can each own their own instance instead of relying on a
// single global process-wide state.
type Engine struct {
	cfg Config
	log *Logger

	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	session   *yamux.Session
	listener  net.Listener
	httpSrv   *http.Server
	running   bool
	connected bool
	lastErr   string

	kaLock          sync.Mutex
	lastKeepAliveID int64

	wg sync.WaitGroup
}

// NewEngine builds an Engine from a config. Call cfg.ApplyDefaults first if
// the config might be missing fields (LoadConfigFile already does this).
func NewEngine(cfg Config, log *Logger) *Engine {
	if log == nil {
		log = NewLogger(LevelInfo)
	}
	return &Engine{cfg: cfg, log: log}
}

// Start begins the tunnel maintenance loop and the local proxy listener. It
// returns once the local listener is up (or failed to start); the tunnel
// connection itself happens in the background and reconnects on its own.
func (e *Engine) Start() error {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return fmt.Errorf("engine already running")
	}
	e.ctx, e.cancel = context.WithCancel(context.Background())
	e.running = true
	e.mu.Unlock()

	e.log.Infof("minewire-cli core v%s starting (proxy=%s mode=%s local=%s remote=%s)",
		Version, e.cfg.ProxyType, e.cfg.Mode, e.cfg.LocalPort, e.cfg.ServerAddress)
	if e.cfg.Mode == ModeRealistic {
		e.log.Infof("realistic throttling: ~%d KB/s (burst %d KB)", e.cfg.RealisticBandwidthKB, e.cfg.RealisticBurstKB)
	}

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.maintainSession()
	}()

	var err error
	if e.cfg.ProxyType == "http" {
		err = e.startHTTPProxy()
	} else {
		err = e.startSOCKSProxy()
	}
	if err != nil {
		// Roll back: don't leave the maintainSession goroutine running if the
		// local listener never came up.
		e.mu.Lock()
		e.running = false
		e.mu.Unlock()
		e.cancel()
		e.wg.Wait()
		return err
	}
	return nil
}

// Stop gracefully shuts the engine down: stops accepting new local
// connections, tears down the tunnel session, and waits for background
// goroutines to exit. Safe to call multiple times, and safe to call again
// after Start (e.g. to reconfigure via a new Engine instance).
func (e *Engine) Stop() error {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return nil
	}
	e.running = false
	cancel := e.cancel
	listener := e.listener
	httpSrv := e.httpSrv
	session := e.session
	e.mu.Unlock()

	e.log.Infof("shutting down")

	if cancel != nil {
		cancel()
	}
	if httpSrv != nil {
		httpSrv.Close()
	}
	if listener != nil {
		listener.Close()
	}
	if session != nil {
		session.Close()
	}

	e.wg.Wait()

	e.mu.Lock()
	e.connected = false
	e.mu.Unlock()

	e.log.Infof("stopped")
	return nil
}

// Status returns a snapshot of the current engine state.
func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	return Status{
		Running:       e.running,
		Connected:     e.connected,
		Mode:          e.cfg.Mode,
		ProxyType:     e.cfg.ProxyType,
		LocalAddr:     e.cfg.LocalPort,
		ServerAddress: e.cfg.ServerAddress,
		LastError:     e.lastErr,
	}
}

// Wait blocks until the engine is stopped. Used by plain CLI mode, which
// just runs until the process receives a signal.
func (e *Engine) Wait() {
	e.wg.Wait()
}

func (e *Engine) setSession(s *yamux.Session) {
	e.mu.Lock()
	e.session = s
	e.connected = s != nil
	e.mu.Unlock()
}

func (e *Engine) getSession() *yamux.Session {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.session
}

func (e *Engine) setLastErr(err error) {
	e.mu.Lock()
	if err != nil {
		e.lastErr = err.Error()
	} else {
		e.lastErr = ""
	}
	e.mu.Unlock()
}

func (e *Engine) startSOCKSProxy() error {
	l, err := net.Listen("tcp", e.cfg.LocalPort)
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
	}
	e.mu.Lock()
	e.listener = l
	e.mu.Unlock()

	e.log.Infof("listening for SOCKS5 on %s", e.cfg.LocalPort)
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				select {
				case <-e.ctx.Done():
					return
				default:
					e.log.Warnf("socks5 accept error: %v", err)
					return
				}
			}
			go e.handleSocks(c)
		}
	}()
	return nil
}

func (e *Engine) startHTTPProxy() error {
	l, err := net.Listen("tcp", e.cfg.LocalPort)
	if err != nil {
		return fmt.Errorf("http listen: %w", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(e.handleHTTP)}
	e.mu.Lock()
	e.listener = l
	e.httpSrv = srv
	e.mu.Unlock()

	e.log.Infof("listening for HTTP CONNECT on %s", e.cfg.LocalPort)
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		if err := srv.Serve(l); err != nil && err != http.ErrServerClosed {
			e.log.Warnf("http proxy error: %v", err)
		}
	}()
	return nil
}
