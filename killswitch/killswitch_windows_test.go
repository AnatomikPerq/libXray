//go:build windows

package killswitch

import (
	"errors"
	"flag"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// The live tests install real filters, under keys of their own and with
// every block narrowed to documentation networks, which nothing on the
// machine uses: whatever happens, they cannot cut it off.
var testKeys = objectKeys{
	provider:   windows.GUID{Data1: 0x5f0c3a71, Data2: 0x1b2e, Data3: 0x4d6f, Data4: [8]byte{0x8a, 0x10, 0x3c, 0x55, 0x9e, 0x21, 0x47, 0x01}},
	sublayer:   windows.GUID{Data1: 0x5f0c3a72, Data2: 0x1b2e, Data3: 0x4d6f, Data4: [8]byte{0x8a, 0x10, 0x3c, 0x55, 0x9e, 0x21, 0x47, 0x01}},
	filterBase: windows.GUID{Data1: 0x5f0c3a73, Data2: 0x1b2e, Data3: 0x0000, Data4: [8]byte{0x8a, 0x10, 0x3c, 0x55, 0x9e, 0x21, 0x47, 0x01}},
}

var testScope = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/32")}

// stage runs one half of the manual check that the unelevated user may lift
// the filters: "engage" elevated, then "lift" from an unelevated process,
// for example a batch file started through explorer.exe.
var stage = flag.String("killswitch.stage", "", "engage or lift, for the manual unelevated check")

func useTestKeys(t *testing.T) {
	t.Helper()
	production := keys
	keys = testKeys
	t.Cleanup(func() { keys = production })
}

func requireElevated(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("installing WFP filters needs administrator rights")
	}
}

// liveOptions permit some other program, not the test, so that the test's
// own connections meet the blocks.
func liveOptions() Options {
	return Options{
		Apps:       []string{filepath.Join(os.Getenv("SystemRoot"), "System32", "notepad.exe")},
		TunLUID:    1,
		AllowLAN:   true,
		Allow:      []netip.Prefix{netip.MustParsePrefix("192.0.2.128/25")},
		blockScope: testScope,
	}
}

// blocked reports whether WFP refused a connection: a block fails at once with
// WSAEACCES, anything else (here, a timeout) means the filters let it pass.
func blocked(t *testing.T, address string) bool {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 700*time.Millisecond)
	if err == nil {
		conn.Close()
		return false
	}
	return errors.Is(err, windows.WSAEACCES)
}

func TestLiveEngageBlocksAndLiftRestores(t *testing.T) {
	if *stage != "" {
		t.Skip("manual stage run")
	}
	requireElevated(t)
	useTestKeys(t)
	t.Cleanup(func() { require.NoError(t, Lift()) })

	require.NoError(t, Engage(liveOptions()))
	engaged, err := Engaged()
	require.NoError(t, err)
	require.True(t, engaged)

	require.True(t, blocked(t, "192.0.2.1:80"), "blocked outside the allowed networks")
	require.False(t, blocked(t, "192.0.2.200:80"), "allowed network passes")
	require.True(t, blocked(t, "192.0.2.200:53"), "DNS stays blocked on the allowed network")

	// Replacing the filters keeps them in force and accepts a new tunnel.
	options := liveOptions()
	options.TunLUID = 2
	options.Allow = nil
	require.NoError(t, Engage(options))
	require.True(t, blocked(t, "192.0.2.200:80"), "the replaced filters no longer allow the network")

	require.NoError(t, Lift())
	engaged, err = Engaged()
	require.NoError(t, err)
	require.False(t, engaged)
	require.False(t, blocked(t, "192.0.2.1:80"), "lifted")
	require.NoError(t, Lift(), "lifting twice is harmless")
}

func TestLivePersistentRoundTrip(t *testing.T) {
	if *stage != "" {
		t.Skip("manual stage run")
	}
	requireElevated(t)
	useTestKeys(t)
	t.Cleanup(func() { require.NoError(t, Lift()) })

	options := liveOptions()
	options.Persistent = true
	require.NoError(t, Engage(options))
	require.True(t, blocked(t, "192.0.2.1:80"))
	// Persistent filters replace dynamic ones and the other way round.
	require.NoError(t, Engage(liveOptions()))
	require.NoError(t, Lift())
	engaged, err := Engaged()
	require.NoError(t, err)
	require.False(t, engaged)
}

func TestLiveEngageNeedsExistingApps(t *testing.T) {
	if *stage != "" {
		t.Skip("manual stage run")
	}
	requireElevated(t)
	useTestKeys(t)
	options := liveOptions()
	options.Apps = []string{filepath.Join(t.TempDir(), "missing.exe")}
	err := Engage(options)
	if err == nil {
		require.NoError(t, Lift())
		t.Skip("FwpmGetAppIdFromFileName0 accepts missing files here")
	}
	engaged, err := Engaged()
	require.NoError(t, err)
	require.False(t, engaged, "a failed engage leaves nothing behind")
}

func TestStage(t *testing.T) {
	useTestKeys(t)
	switch *stage {
	case "":
		t.Skip("run with -killswitch.stage")
	case "engage":
		requireElevated(t)
		require.NoError(t, Engage(liveOptions()))
	case "lift":
		t.Logf("elevated: %v", windows.GetCurrentProcessToken().IsElevated())
		engaged, err := Engaged()
		require.NoError(t, err)
		require.True(t, engaged, "engage first")
		require.NoError(t, Lift())
		engaged, err = Engaged()
		require.NoError(t, err)
		require.False(t, engaged)
	default:
		t.Fatalf("unknown stage %q", *stage)
	}
}
