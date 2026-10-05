//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
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
