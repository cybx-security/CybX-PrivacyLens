//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// isElevated reports whether the process holds administrator rights (an
// elevated token, or a service account such as SYSTEM).
func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// relaunchElevated restarts this executable with args through a UAC prompt.
// It returns once the new process has been started (or the prompt was
// declined); the elevated copy runs in a console window of its own.
func relaunchElevated(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = syscall.EscapeArg(a)
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, err := syscall.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	params, err := syscall.UTF16PtrFromString(strings.Join(quoted, " "))
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, file, params, nil, windows.SW_SHOWNORMAL)
}

// removeDirAfterExit deletes dir once this process has exited. A running
// executable cannot delete itself on Windows, so a detached cmd.exe waits a
// few seconds (ping is the portable sleep) and then removes the folder.
func removeDirAfterExit(dir string) error {
	if strings.ContainsAny(dir, `"%&|<>^`) {
		return fmt.Errorf("refusing to schedule removal of unusual path %q", dir)
	}
	cmd := exec.Command("cmd.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// Raw command line: Go's argument quoting is not cmd.exe's.
		CmdLine:       fmt.Sprintf(`cmd.exe /d /c "ping -n 4 127.0.0.1 >nul & rmdir /s /q "%s""`, dir),
		HideWindow:    true,
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_NO_WINDOW,
	}
	cmd.Dir = os.TempDir() // not inside the folder being removed
	return cmd.Start()
}

// The Start Menu shortcut and the registry entries below are written with
// direct Windows API calls rather than by running powershell.exe or reg.exe.
// A newly installed, not-yet-reputable program that spawns PowerShell with
// -ExecutionPolicy Bypass and then registers a SYSTEM scheduled task is,
// to antivirus behavior monitoring, indistinguishable from a dropper: in
// testing, Microsoft Defender flagged exactly that sequence
// (Behavior:Win32/Persistence.A!ml) and blocked the program from running.

var (
	modole32             = windows.NewLazySystemDLL("ole32.dll")
	procCoCreateInstance = modole32.NewProc("CoCreateInstance")

	clsidShellLink = windows.GUID{Data1: 0x00021401, Data4: [8]byte{0xC0, 0, 0, 0, 0, 0, 0, 0x46}}
	iidShellLinkW  = windows.GUID{Data1: 0x000214F9, Data4: [8]byte{0xC0, 0, 0, 0, 0, 0, 0, 0x46}}
	iidPersistFile = windows.GUID{Data1: 0x0000010B, Data4: [8]byte{0xC0, 0, 0, 0, 0, 0, 0, 0x46}}
)

// Method slots in the IShellLinkW and IPersistFile vtables (after the three
// IUnknown methods), from shobjidl_core.h and objidl.h.
const (
	comQueryInterface = 0
	comRelease        = 2

	shellLinkSetDescription      = 7
	shellLinkSetWorkingDirectory = 9
	shellLinkSetArguments        = 11
	shellLinkSetPath             = 20

	persistFileSave = 6
)

// comCall invokes one method of a COM object through its vtable and turns a
// failure HRESULT into an error.
func comCall(obj unsafe.Pointer, method int, args ...uintptr) error {
	vtable := *(*unsafe.Pointer)(obj)
	fn := *(*uintptr)(unsafe.Add(vtable, uintptr(method)*unsafe.Sizeof(uintptr(0))))
	r, _, _ := syscall.SyscallN(fn, append([]uintptr{uintptr(obj)}, args...)...)
	if int32(r) < 0 {
		return fmt.Errorf("shell link call %d failed (HRESULT 0x%08X)", method, uint32(r))
	}
	return nil
}

// createShortcut writes a .lnk file through the shell's own IShellLink
// object - the same thing Explorer's "Create shortcut" does.
func createShortcut(lnk, target, args, workDir, description string) error {
	runtime.LockOSThread() // COM initialization is per thread
	defer runtime.UnlockOSThread()
	if err := windows.CoInitializeEx(0, windows.COINIT_APARTMENTTHREADED); err == nil {
		defer windows.CoUninitialize()
	}

	var link unsafe.Pointer
	r, _, _ := procCoCreateInstance.Call(
		uintptr(unsafe.Pointer(&clsidShellLink)), 0, windows.CLSCTX_INPROC_SERVER,
		uintptr(unsafe.Pointer(&iidShellLinkW)), uintptr(unsafe.Pointer(&link)))
	if int32(r) < 0 || link == nil {
		return fmt.Errorf("cannot create a shell link object (HRESULT 0x%08X)", uint32(r))
	}
	defer comCall(link, comRelease)

	for _, set := range []struct {
		method int
		value  string
	}{
		{shellLinkSetPath, target},
		{shellLinkSetArguments, args},
		{shellLinkSetWorkingDirectory, workDir},
		{shellLinkSetDescription, description},
	} {
		p, err := windows.UTF16PtrFromString(set.value)
		if err != nil {
			return err
		}
		if err := comCall(link, set.method, uintptr(unsafe.Pointer(p))); err != nil {
			return err
		}
	}

	var file unsafe.Pointer
	if err := comCall(link, comQueryInterface, uintptr(unsafe.Pointer(&iidPersistFile)), uintptr(unsafe.Pointer(&file))); err != nil {
		return err
	}
	defer comCall(file, comRelease)
	path, err := windows.UTF16PtrFromString(lnk)
	if err != nil {
		return err
	}
	return comCall(file, persistFileSave, uintptr(unsafe.Pointer(path)), 1)
}

// The registry locations, relative to HKEY_LOCAL_MACHINE. WOW64_64KEY keeps
// them in the 64-bit view whatever the process.
const (
	uninstallKeyPath = `Software\Microsoft\Windows\CurrentVersion\Uninstall\PrivacyLens`
	machineEnvPath   = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
)

// writeUninstallEntry registers PrivacyLens in the "Installed apps" list.
func writeUninstallEntry(vals []regValue) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, uninstallKeyPath, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer k.Close()
	for _, v := range vals {
		if v.kind == "REG_DWORD" {
			var n uint32
			fmt.Sscan(v.data, &n)
			err = k.SetDWordValue(v.name, n)
		} else {
			err = k.SetStringValue(v.name, v.data)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// deleteUninstallEntry removes the "Installed apps" entry; a missing entry
// is not an error.
func deleteUninstallEntry() error {
	err := registry.DeleteKey(registry.LOCAL_MACHINE, uninstallKeyPath)
	if err == registry.ErrNotExist {
		return nil
	}
	return err
}

// deleteMachineEnv removes a machine-wide environment variable; a missing
// one is not an error.
func deleteMachineEnv(name string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, machineEnvPath, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.DeleteValue(name); err != nil && err != registry.ErrNotExist {
		return err
	}
	return nil
}
