package core

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Level is a log severity level.
type Level int

const (
	LevelError Level = iota
	LevelWarn
	LevelInfo
	LevelDebug
)

func (l Level) String() string {
	switch l {
	case LevelError:
		return "ERROR"
	case LevelWarn:
		return "WARN"
	case LevelInfo:
		return "INFO"
	case LevelDebug:
		return "DEBUG"
	default:
		return "UNKNOWN"
	}
}

// ParseLevel parses a level name (case-insensitive; "warning" accepted as an
// alias for "warn").
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "error":
		return LevelError, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "info":
		return LevelInfo, nil
	case "debug":
		return LevelDebug, nil
	default:
		return LevelInfo, fmt.Errorf("unknown log level %q", s)
	}
}

// LogSink receives every log line that passes the current level filter, in
// addition to it being written to the Logger's output stream. Used by the
// daemon to forward logs as JSON events, and by the mobile wrapper to
// forward logs to a host-language callback.
type LogSink func(level Level, message string)

// Logger is a small leveled logger. Safe for concurrent use.
type Logger struct {
	mu    sync.Mutex
	level Level
	out   *os.File
	sink  LogSink
}

// NewLogger creates a Logger writing to stderr at the given level.
func NewLogger(level Level) *Logger {
	return &Logger{level: level, out: os.Stderr}
}

// SetLevel changes the minimum level that gets logged.
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// SetSink installs (or, if nil, removes) a callback invoked for every log
// line that passes the level filter.
func (l *Logger) SetSink(sink LogSink) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sink = sink
}

func (l *Logger) log(level Level, format string, args ...interface{}) {
	l.mu.Lock()
	cur := l.level
	sink := l.sink
	l.mu.Unlock()

	if level > cur {
		return
	}
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("%s [%s] %s", time.Now().Format("2006-01-02 15:04:05"), level.String(), msg)
	fmt.Fprintln(l.out, line)
	if sink != nil {
		sink(level, msg)
	}
}

func (l *Logger) Errorf(format string, args ...interface{}) { l.log(LevelError, format, args...) }
func (l *Logger) Warnf(format string, args ...interface{})  { l.log(LevelWarn, format, args...) }
func (l *Logger) Infof(format string, args ...interface{})  { l.log(LevelInfo, format, args...) }
func (l *Logger) Debugf(format string, args ...interface{}) { l.log(LevelDebug, format, args...) }
