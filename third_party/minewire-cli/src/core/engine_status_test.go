package core

import (
	"net"
	"testing"

	"github.com/hashicorp/yamux"
)

// libXray patch: Status follows the session, not only the last login.
func TestStatusReportsADroppedSessionAsDisconnected(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	session, err := yamux.Client(client, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{}
	e.setSession(session)
	if !e.Status().Connected {
		t.Fatal("a live session is not connected")
	}
	session.Close()
	if e.Status().Connected {
		t.Fatal("a closed session is still connected")
	}
}
