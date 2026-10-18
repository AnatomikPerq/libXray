package minewire

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/dmitrymodder/minewire-cli/src/core"
)

// maxLogBytes bounds one diagnostics file; the previous one is kept as
// "<path>.1", so a session never takes more than twice this on disk.
// A variable only for tests.
var maxLogBytes int64 = 1 << 20

// logFile is an append-only diagnostics file shared by every engine that
// names the same path. Engines run inside a GUI App, whose stderr goes
// nowhere: without a file, a session that keeps dropping leaves no trace.
//
// Each write opens and closes the file. Lines are rare (logins, drops,
// errors), and no handle stays open for the user to trip over on Windows.
type logFile struct {
	mu   sync.Mutex
	path string
}

var (
	logsMu sync.Mutex
	logs   = map[string]*logFile{}
)

func sharedLog(path string) *logFile {
	logsMu.Lock()
	defer logsMu.Unlock()
	if log, ok := logs[path]; ok {
		return log
	}
	log := &logFile{path: path}
	logs[path] = log
	return log
}

// Write appends p, rotating first when p would not fit. Failures are
// swallowed: diagnostics must never break a tunnel.
func (l *logFile) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if info, err := os.Stat(l.path); err == nil && info.Size()+int64(len(p)) > maxLogBytes {
		// os.Rename replaces an existing target on Windows as well.
		os.Rename(l.path, l.path+".1")
	}
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return len(p), nil
	}
	file.Write(p)
	file.Close()
	return len(p), nil
}

// engineLog writes one engine's lines, tagged with its local port so the
// lines of several engines in one file stay apart.
type engineLog struct {
	file *logFile
	port int
}

func (e engineLog) line(level core.Level, message string) {
	fmt.Fprintf(e.file, "%s [%s] engine %d: %s\n",
		time.Now().Format("2006-01-02 15:04:05"), level.String(), e.port, message)
}

// Write takes yamux's lines, which carry their own timestamp.
func (e engineLog) Write(p []byte) (int, error) {
	fmt.Fprintf(e.file, "engine %d: %s", e.port, p)
	return len(p), nil
}
