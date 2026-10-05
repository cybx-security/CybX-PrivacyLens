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
