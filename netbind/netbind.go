// Package netbind pins sockets to one network interface, so they leave
// through it whatever the routing table prefers: minewire uplinks in TUN mode
// and network report probes on the network the user picked.
package netbind

import "syscall"

// Control returns a net.Dialer/net.ListenConfig Control function binding
// every socket to the named interface, or nil for an empty name.
func Control(name string) func(network, address string, conn syscall.RawConn) error {
	if name == "" {
		return nil
	}
	return func(network, address string, conn syscall.RawConn) error {
		return Bind(name, network, address, conn)
	}
}
