package minewire

import "syscall"

func bindToInterface(name, _, _ string, conn syscall.RawConn) error {
	var bindErr error
	err := conn.Control(func(fd uintptr) {
		bindErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, name)
	})
	if err != nil {
		return err
	}
	return bindErr
}
