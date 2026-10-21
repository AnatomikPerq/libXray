//go:build !windows

package killswitch

import (
	"os"
	"strings"
)

// CurrentSession reads the boot of this machine and the login session, where
// the system tells them.
func CurrentSession() Session {
	var session Session
	if id, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		session.Logon = strings.TrimSpace(string(id))
	}
	if login := os.Getenv("XDG_SESSION_ID"); login != "" {
		session.Logon += "/" + login
	}
	return session
}
