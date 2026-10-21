package killswitch

// Session identifies the user's session on this machine, so that the App can
// tell a block left from the current session from one left before the user
// logged off or the machine restarted. Windows' fast startup keeps the
// filters and the boot time across a shutdown, but not the logon.
type Session struct {
	// BootedAt is when the machine booted, in Unix milliseconds. Clock
	// corrections move it by a little; compare it with some tolerance.
	BootedAt int64 `json:"bootedAt"`
	// Logon names the user's logon session; empty when it cannot be read.
	Logon string `json:"logon"`
}
