package netbind

import (
	"net"
	"sync/atomic"
	"testing"
)

func TestProtectorSeesEverySocket(t *testing.T) {
	if Control("") != nil {
		t.Fatal("no interface and no protector must leave sockets alone")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	var protected atomic.Int32
	SetProtector(func(fd uintptr) bool {
		protected.Add(1)
		// A failed protect (no VPN prepared) must not stop the dial.
		return false
	})
	defer SetProtector(nil)
	if !Protecting() {
		t.Fatal("protector not registered")
	}

	dialer := net.Dialer{Control: Control("")}
	conn, err := dialer.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if protected.Load() != 1 {
		t.Fatalf("protected %d sockets, want 1", protected.Load())
	}

	SetProtector(nil)
	if Protecting() || Control("") != nil {
		t.Fatal("protector not removed")
	}
}
