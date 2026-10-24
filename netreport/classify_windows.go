package netreport

import "syscall"

func classifyErrno(errno syscall.Errno) Status {
	switch errno {
	case 10054, 10053, 64, 1236: // WSAECONNRESET, WSAECONNABORTED, ERROR_NETNAME_DELETED, ERROR_CONNECTION_ABORTED
		return StatusReset
	case 10061, 1225: // WSAECONNREFUSED, ERROR_CONNECTION_REFUSED
		return StatusRefused
	case 10051, 10065, 1231, 1232: // WSAENETUNREACH, WSAEHOSTUNREACH, ERROR_NETWORK_UNREACHABLE, ERROR_HOST_UNREACHABLE
		return StatusUnreachable
	case 10060, 121: // WSAETIMEDOUT, ERROR_SEM_TIMEOUT
		return StatusTimeout
	}
	return ""
}
