//go:build !windows && !linux

package minewire

import "syscall"

// Elsewhere the platform's VPN setup decides whether the App's own traffic
// enters the tunnel; there is nothing to bind here.
func bindToInterface(_, _, _ string, _ syscall.RawConn) error { return nil }
