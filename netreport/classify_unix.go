//go:build !windows

package netreport

import "syscall"

func classifyErrno(errno syscall.Errno) Status {
	switch errno {
	case syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE:
		return StatusReset
	case syscall.ECONNREFUSED:
		return StatusRefused
	case syscall.ENETUNREACH, syscall.EHOSTUNREACH:
		return StatusUnreachable
	case syscall.ETIMEDOUT:
		return StatusTimeout
	}
	return ""
}
