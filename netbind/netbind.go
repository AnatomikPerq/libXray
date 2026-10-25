// Package netbind pins sockets to one network interface, so they leave
// through it whatever the routing table prefers: minewire uplinks in TUN mode
// and network report probes on the network the user picked. On Android it
// instead keeps them out of the App's own VPN through a registered protector.
package netbind

import (
	"sync/atomic"
	"syscall"
)

var protector atomic.Pointer[func(fd uintptr) bool]

// SetProtector registers how this process keeps a socket out of the VPN its
// app runs (Android: VpnService.protect, which works in every process of the
// VPN app, not only the service's). nil removes it.
func SetProtector(protect func(fd uintptr) bool) {
	if protect == nil {
		protector.Store(nil)
		return
	}
	protector.Store(&protect)
}

// Protecting reports whether a protector is registered.
func Protecting() bool { return protector.Load() != nil }

// Control returns a net.Dialer/net.ListenConfig Control function binding
// every socket to the named interface and protecting it, or nil when there
// is neither an interface nor a protector.
func Control(name string) func(network, address string, conn syscall.RawConn) error {
	protect := protector.Load()
	if name == "" && protect == nil {
		return nil
	}
	return func(network, address string, conn syscall.RawConn) error {
		if protect != nil {
			// Protecting fails while no VPN of this app is prepared; the
			// socket still dials, as there is no tunnel to escape then.
			_ = conn.Control(func(fd uintptr) { (*protect)(fd) })
		}
		if name == "" {
			return nil
		}
		return Bind(name, network, address, conn)
	}
}
