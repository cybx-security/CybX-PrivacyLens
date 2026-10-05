//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// alert shows a native error dialog: a -H=windowsgui process has no console,
// so a message box is the only way a startup failure reaches the user.
func alert(msg string) {
	const mbIconError = 0x10
	text, terr := syscall.UTF16PtrFromString(msg)
	title, cerr := syscall.UTF16PtrFromString("PrivacyLens")
	if terr != nil || cerr != nil {
		return
	}
	syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW").
		Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), mbIconError)
}
