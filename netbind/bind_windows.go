package netbind

import (
	"encoding/binary"
	"net"
	"strings"
	"syscall"
)

// IP_UNICAST_IF and IPV6_UNICAST_IF, as Xray uses them for sockopt.interface.
const unicastIf = 31

func Bind(name, network, address string, conn syscall.RawConn) error {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	var bindErr error
	err = conn.Control(func(fd uintptr) {
		handle := syscall.Handle(fd)
		if isIPv4(network, address) {
			// IPv4 wants the index in network byte order.
			var index [4]byte
			binary.BigEndian.PutUint32(index[:], uint32(iface.Index))
			bindErr = syscall.SetsockoptInt(handle, syscall.IPPROTO_IP, unicastIf, int(binary.LittleEndian.Uint32(index[:])))
			return
		}
		bindErr = syscall.SetsockoptInt(handle, syscall.IPPROTO_IPV6, unicastIf, iface.Index)
	})
	if err != nil {
		return err
	}
	return bindErr
}

// isIPv4 picks the option family. The network names it when the caller asked
// for one ("udp4"); otherwise the address does (the remote one for a dial,
// the local one for a listen).
func isIPv4(network, address string) bool {
	switch {
	case strings.HasSuffix(network, "4"):
		return true
	case strings.HasSuffix(network, "6"):
		return false
	}
	return strings.Contains(address, ".")
}
