//go:build windows

package main

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	moduser32            = windows.NewLazySystemDLL("user32.dll")
	procRegisterClassExW = moduser32.NewProc("RegisterClassExW")
	procCreateWindowExW  = moduser32.NewProc("CreateWindowExW")
	procDefWindowProcW   = moduser32.NewProc("DefWindowProcW")
	procGetMessageW      = moduser32.NewProc("GetMessageW")
	procDispatchMessageW = moduser32.NewProc("DispatchMessageW")
)

const (
	wmQueryEndSession = 0x0011
	wmEndSession      = 0x0016
)

type wndClassEx struct {
	size       uint32
	style      uint32
	wndProc    uintptr
	clsExtra   int32
	wndExtra   int32
	instance   windows.Handle
	icon       windows.Handle
	cursor     windows.Handle
	background windows.Handle
	menuName   *uint16
	className  *uint16
	iconSm     windows.Handle
}

type windowMessage struct {
	hwnd    windows.HWND
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      struct{ x, y int32 }
	private uint32
}

// watchSessionEnd calls onEnd when Windows ends the user's session: log off,
// shut down or restart, fast startup included. A console process cannot rely
// on console control events for that (they stop once user32 is loaded, and
// are meant for services), so it keeps a hidden top-level window, which
// Windows asks before ending the session. onEnd runs inside WM_ENDSESSION:
// once that returns, the process may be terminated at any moment.
func watchSessionEnd(onEnd func()) error {
	_, err := sessionEndWindow(onEnd)
	return err
}

// sessionEndWindow returns the window, so that tests can send it the message.
func sessionEndWindow(onEnd func()) (windows.HWND, error) {
	created := make(chan windows.HWND, 1)
	failed := make(chan error, 1)
	go func() {
		// The window belongs to this thread, and so do its messages.
		runtime.LockOSThread()
		className, _ := windows.UTF16PtrFromString("HyperClientCoreSession")
		var instance windows.Handle
		if err := windows.GetModuleHandleEx(0, nil, &instance); err != nil {
			failed <- err
			return
		}
		ended := false
		class := wndClassEx{
			wndProc: windows.NewCallback(func(hwnd windows.HWND, message uint32, wParam, lParam uintptr) uintptr {
				switch message {
				case wmQueryEndSession:
					return 1
				case wmEndSession:
					if wParam != 0 && !ended {
						ended = true
						onEnd()
					}
					return 0
				}
				result, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(message), wParam, lParam)
				return result
			}),
			instance:  instance,
			className: className,
		}
		class.size = uint32(unsafe.Sizeof(class))
		if atom, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&class))); atom == 0 {
			failed <- err
			return
		}
		// Never shown, but top-level: message-only windows miss the
		// broadcast that ends the session.
		hwnd, _, err := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(className)),
			0, 0, 0, 0, 0, 0, 0, uintptr(instance), 0)
		if hwnd == 0 {
			failed <- err
			return
		}
		created <- windows.HWND(hwnd)
		var message windowMessage
		for {
			result, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0)
			if int32(result) <= 0 {
				return
			}
			procDispatchMessageW.Call(uintptr(unsafe.Pointer(&message)))
		}
	}()
	select {
	case hwnd := <-created:
		return hwnd, nil
	case err := <-failed:
		if err == nil {
			err = errors.New("session end window failed")
		}
		return 0, err
	}
}
