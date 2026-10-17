package minewire

import (
	"context"
	"net"
	"syscall"
)

// boundDialer dials through the named interface. If the interface is gone
// or refuses the option, it dials unbound: the App's bypass rule still sends
// the uplink out of the tunnel, only through the Core.
func boundDialer(name string) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		bound := net.Dialer{
			Control: func(network, address string, conn syscall.RawConn) error {
				return bindToInterface(name, network, address, conn)
			},
		}
		conn, err := bound.DialContext(ctx, network, address)
		if err == nil || ctx.Err() != nil {
			return conn, err
		}
		var unbound net.Dialer
		return unbound.DialContext(ctx, network, address)
	}
}
