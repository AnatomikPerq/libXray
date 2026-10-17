package minewire

import (
	"encoding/binary"
	"net"
	"strings"
	"syscall"
)

// IP_UNICAST_IF and IPV6_UNICAST_IF, as Xray uses them for sockopt.interface.
const unicastIf = 31

func bindToInterface(name, network, address string, conn syscall.RawConn) error {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	var bindErr error
	err = conn.Control(func(fd uintptr) {
		handle := syscall.Handle(fd)
		if strings.Contains(address, ".") {
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
