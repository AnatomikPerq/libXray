//go:build windows

package main

import (
	"testing"
	"time"
)

func TestSessionEndRunsOnceOnEndSession(t *testing.T) {
	ended := make(chan struct{}, 2)
	hwnd, err := sessionEndWindow(func() { ended <- struct{}{} })
	if err != nil {
		t.Fatal(err)
	}
	send := func(message, wParam uintptr) uintptr {
		result, _, _ := moduser32.NewProc("SendMessageW").Call(uintptr(hwnd), message, wParam, 0)
		return result
	}
	if send(wmQueryEndSession, 0) != 1 {
		t.Fatal("the session end was refused")
	}
	// A cancelled session end (wParam false) is not an end.
	send(wmEndSession, 0)
	select {
	case <-ended:
		t.Fatal("ran on a cancelled session end")
	default:
	}
	send(wmEndSession, 1)
	send(wmEndSession, 1)
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("did not run on the session end")
	}
	select {
	case <-ended:
		t.Fatal("ran twice")
	default:
	}
}
