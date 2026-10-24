//go:build !windows && !linux

package netbind

import "syscall"

// Elsewhere the platform's VPN setup decides whether the App's own traffic
// enters the tunnel; there is nothing to bind here.
func Bind(_, _, _ string, _ syscall.RawConn) error { return nil }
