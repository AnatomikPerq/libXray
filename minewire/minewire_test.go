package minewire

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
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

// A missing interface must not cost the connection: the bypass rule still
// keeps the uplink out of the tunnel.
func TestBoundDialerFallsBackWhenTheInterfaceIsGone(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		if conn, err := listener.Accept(); err == nil {
			conn.Close()
		}
	}()
	dial := boundDialer("no such interface 7f3a")
	conn, err := dial(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()
}

// Without the defaults the realistic throttle has a zero rate and an upload
// write never returns.
func TestEngineConfig(t *testing.T) {
	cfg := engineConfig(StartOptions{
		ServerAddress: "127.0.0.1:1",
		Password:      "secret",
		Mode:          "realistic",
	}, 1080)
	if cfg.Mode != "realistic" || cfg.RealisticBandwidthKB <= 0 || cfg.RealisticBurstKB <= 0 {
		t.Fatalf("realistic config: %+v", cfg)
	}
	if cfg.LocalPort != "127.0.0.1:1080" || cfg.ProxyType != "socks5" || cfg.Dial != nil {
		t.Fatalf("listener config: %+v", cfg)
	}
	if engineConfig(StartOptions{Mode: "turbo"}, 1).Mode != "fast" {
		t.Fatal("unknown mode is not fast")
	}
	if engineConfig(StartOptions{Interface: "Ethernet"}, 1).Dial == nil {
		t.Fatal("interface without a bound dialer")
	}
}

func TestEngineWritesItsLogFile(t *testing.T) {
	t.Cleanup(func() { Stop(0) })
	path := filepath.Join(t.TempDir(), "minewire.log")
	port, err := Start(StartOptions{
		ServerAddress: "127.0.0.1:1",
		Password:      "secret",
		Mode:          "fast",
		LogFile:       path,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("engine %d: connect failed", port)
	deadline := time.Now().Add(5 * time.Second)
	for {
		data, _ := os.ReadFile(path)
		if strings.Contains(string(data), want) {
			if strings.Contains(string(data), "secret") {
				t.Fatalf("the password leaked into the log:\n%s", data)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("log has no %q:\n%s", want, data)
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, state := range State() {
		if state.LocalPort == port && (state.Connected || state.LastError == "") {
			t.Fatalf("an unreachable server reports %+v", state)
		}
	}
}

func TestLogFileRotates(t *testing.T) {
	previous := maxLogBytes
	maxLogBytes = 64
	t.Cleanup(func() { maxLogBytes = previous })
	path := filepath.Join(t.TempDir(), "minewire.log")
	log := &logFile{path: path}
	line := []byte(strings.Repeat("x", 40) + "\n")
	for i := 0; i < 3; i++ {
		log.Write(line)
	}
	current, _ := os.ReadFile(path)
	rotated, _ := os.ReadFile(path + ".1")
	if len(current) != len(line) || len(rotated) != len(line) {
		t.Fatalf("current %d bytes, rotated %d bytes", len(current), len(rotated))
	}
}
