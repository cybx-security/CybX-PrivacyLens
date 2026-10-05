//go:build !windows

package main

import (
	"errors"
	"os"
)

// isElevated reports whether the process runs as root.
func isElevated() bool { return os.Geteuid() == 0 }

// relaunchElevated is Windows-only (UAC); elsewhere the user re-runs under
// sudo.
func relaunchElevated([]string) error { return errors.New("not supported on this platform") }

// removeDirAfterExit is Windows-only: other platforms can delete a running
// program's files directly.
func removeDirAfterExit(string) error { return errors.New("not supported on this platform") }

// The Start Menu shortcut, Installed-apps entry, and machine environment
// are Windows concepts; these exist so the shared code compiles everywhere.
func createShortcut(lnk, target, args, workDir, description string) error {
	return errors.New("not supported on this platform")
}
func writeUninstallEntry([]regValue) error { return errors.New("not supported on this platform") }
func deleteUninstallEntry() error          { return nil }
func deleteMachineEnv(string) error        { return nil }
