//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var (
	shell32           = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteW = shell32.NewProc("ShellExecuteW")
)

// openBrowser opens url with the OS's default handler via a direct
// ShellExecuteW call — the same API "cmd /c start" and Explorer's "Run"
// dialog both ultimately use, called here without going through cmd.exe
// (or any other intermediate process) at all. That matters specifically
// because this binary is built with the GUI subsystem on Windows (no
// console of its own): spawning cmd.exe, a console-subsystem process,
// would otherwise flash its console window for an instant even though
// this binary has none.
func openBrowser(url string) {
	urlPtr, err := syscall.UTF16PtrFromString(url)
	if err != nil {
		return
	}
	verbPtr, err := syscall.UTF16PtrFromString("open")
	if err != nil {
		return
	}
	const swShowNormal = 1
	_, _, _ = procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(urlPtr)),
		0,
		0,
		swShowNormal,
	)
}
