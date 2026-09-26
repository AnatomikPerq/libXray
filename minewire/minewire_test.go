package minewire

import (
	"net"
	"strconv"
	"testing"
)

// The server is unreachable on purpose: engines listen at once and connect in
// the background, which is all these lifecycle checks need.
func start(t *testing.T) int {
	t.Helper()
	port, err := Start(StartOptions{
		ServerAddress: "127.0.0.1:1",
		Password:      "secret",
		Mode:          "fast",
	})
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func TestEnginesRunSideBySideAndStopByPort(t *testing.T) {
	t.Cleanup(func() { Stop(0) })
	first := start(t)
	second := start(t)
	if first == second {
		t.Fatalf("both engines got port %d", first)
	}
	if got := len(State()); got != 2 {
		t.Fatalf("running engines = %d, want 2", got)
	}

	for _, port := range []int{first, second} {
		conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("engine on %d does not listen: %v", port, err)
		}
		conn.Close()
	}

	if err := Stop(first); err != nil {
		t.Fatal(err)
	}
	states := State()
	if len(states) != 1 || states[0].LocalPort != second {
		t.Fatalf("after stopping %d: %+v", first, states)
	}
	if err := Stop(0); err != nil {
		t.Fatal(err)
	}
	if got := len(State()); got != 0 {
		t.Fatalf("engines left after Stop(0): %d", got)
	}
	// Idempotent.
	if err := Stop(second); err != nil {
		t.Fatal(err)
	}
}

func TestStartRejectsMissingCredentials(t *testing.T) {
	if _, err := Start(StartOptions{ServerAddress: "127.0.0.1:1"}); err == nil {
		t.Fatal("started without a password")
	}
	if _, err := Start(StartOptions{Password: "secret"}); err == nil {
		t.Fatal("started without a server")
	}
}

func TestListenerIsLoopbackOnly(t *testing.T) {
	t.Cleanup(func() { Stop(0) })
	port := start(t)
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Skip(err)
	}
	for _, address := range addresses {
		ip, _, _ := net.ParseCIDR(address.String())
		if ip == nil || ip.IsLoopback() || ip.To4() == nil {
			continue
		}
		conn, err := net.Dial("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		if err == nil {
			conn.Close()
			t.Fatalf("engine reachable on %s", ip)
		}
	}
}
