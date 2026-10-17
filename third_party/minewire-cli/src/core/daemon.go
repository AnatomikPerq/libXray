package core

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// Command is one line of JSON sent to the daemon on its input stream.
//
//	{"cmd":"start","config":{...}}   - (re)configure and start the engine
//	{"cmd":"stop"}                   - stop the tunnel + local proxy
//	{"cmd":"status"}                 - request an immediate status event
//	{"cmd":"shutdown"}               - stop everything and exit the process
type Command struct {
	Cmd    string  `json:"cmd"`
	Config *Config `json:"config,omitempty"`
}

// Event is one line of JSON the daemon writes to its output stream.
//
//	{"event":"status","data":{...}}
//	{"event":"log","level":"info","message":"..."}
//	{"event":"error","message":"..."}
//	{"event":"shutdown"}
type Event struct {
	Event   string      `json:"event"`
	Level   string      `json:"level,omitempty"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// Daemon wraps an Engine with a line-delimited JSON control protocol, meant
// to be driven over a child process's stdin/stdout by a desktop UI. One
// Daemon manages at most one Engine at a time; sending "start" again swaps
// in a freshly configured Engine after stopping the old one.
type Daemon struct {
	log *Logger

	mu     sync.Mutex
	engine *Engine

	outMu  sync.Mutex
	encOut *json.Encoder
}

// NewDaemon creates a Daemon that writes events (including forwarded log
// lines) to out as newline-delimited JSON.
func NewDaemon(log *Logger, out io.Writer) *Daemon {
	if log == nil {
		log = NewLogger(LevelInfo)
	}
	d := &Daemon{log: log, encOut: json.NewEncoder(out)}
	log.SetSink(func(level Level, msg string) {
		d.emit(Event{Event: "log", Level: level.String(), Message: msg})
	})
	return d
}

func (d *Daemon) emit(ev Event) {
	d.outMu.Lock()
	defer d.outMu.Unlock()
	d.encOut.Encode(ev)
}

func (d *Daemon) emitStatus() {
	d.mu.Lock()
	e := d.engine
	d.mu.Unlock()
	if e == nil {
		d.emit(Event{Event: "status", Data: Status{}})
		return
	}
	d.emit(Event{Event: "status", Data: e.Status()})
}

// Run reads newline-delimited JSON commands from in until it's closed or a
// "shutdown" command is received. It blocks until the daemon should exit.
// If the input stream closes unexpectedly (e.g. the UI process died), the
// engine is stopped rather than left running orphaned.
func (d *Daemon) Run(in io.Reader) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var cmd Command
		if err := json.Unmarshal(line, &cmd); err != nil {
			d.emit(Event{Event: "error", Message: fmt.Sprintf("invalid command: %v", err)})
			continue
		}

		switch cmd.Cmd {
		case "start":
			d.handleStart(cmd.Config)
		case "stop":
			d.handleStop()
		case "status":
			d.emitStatus()
		case "shutdown":
			d.handleStop()
			d.emit(Event{Event: "shutdown"})
			return nil
		default:
			d.emit(Event{Event: "error", Message: fmt.Sprintf("unknown command: %q", cmd.Cmd)})
		}
	}
	d.handleStop()
	return scanner.Err()
}

func (d *Daemon) handleStart(cfg *Config) {
	if cfg == nil {
		d.emit(Event{Event: "error", Message: "start requires a config"})
		return
	}
	cfg.ApplyDefaults(d.log)

	d.mu.Lock()
	if d.engine != nil {
		d.engine.Stop()
	}
	e := NewEngine(*cfg, d.log)
	d.engine = e
	d.mu.Unlock()

	if err := e.Start(); err != nil {
		d.emit(Event{Event: "error", Message: fmt.Sprintf("start failed: %v", err)})
		return
	}
	d.emitStatus()
}

func (d *Daemon) handleStop() {
	d.mu.Lock()
	e := d.engine
	d.mu.Unlock()
	if e == nil {
		return
	}
	e.Stop()
	d.emitStatus()
}
