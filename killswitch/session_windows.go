//go:build windows

package killswitch

import (
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// tokenStatistics is TOKEN_STATISTICS.
type tokenStatistics struct {
	tokenID            windows.LUID
	authenticationID   windows.LUID
	expirationTime     int64
	tokenType          uint32
	impersonationLevel uint32
	dynamicCharged     uint32
	dynamicAvailable   uint32
	groupCount         uint32
	privilegeCount     uint32
	modifiedID         windows.LUID
}

// CurrentSession reads the boot time and the logon session of this process.
// An elevated process has a logon session of its own: compare only values
// read by processes of the same elevation.
func CurrentSession() Session {
	session := Session{BootedAt: time.Now().Add(-windows.DurationSinceBoot()).UnixMilli()}
	var stats tokenStatistics
	var length uint32
	err := windows.GetTokenInformation(windows.GetCurrentProcessToken(), windows.TokenStatistics,
		(*byte)(unsafe.Pointer(&stats)), uint32(unsafe.Sizeof(stats)), &length)
	if err == nil {
		id := stats.authenticationID
		session.Logon = fmt.Sprintf("%x-%x", uint32(id.HighPart), id.LowPart)
	}
	return session
}
