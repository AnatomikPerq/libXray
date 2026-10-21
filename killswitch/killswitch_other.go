//go:build !windows

package killswitch

// Engage is not available on this platform.
func Engage(Options) error { return ErrUnsupported }

// Lift has nothing to remove on this platform.
func Lift() error { return nil }

// Engaged is always false on this platform.
func Engaged() (bool, error) { return false, nil }
