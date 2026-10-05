// Package paths resolves the per-user PrivacyLens data directory, where
// scans are saved automatically when the user doesn't specify outputs — so
// results are never silently lost, with zero configuration.
package paths

import (
	"os"
	"path/filepath"
	"runtime"
)

// DataDir returns the PrivacyLens data directory for the current user,
// creating it if needed:
//
//	Windows:  %LOCALAPPDATA%\PrivacyLens
//	macOS:    ~/Library/Application Support/PrivacyLens
//	Linux:    $XDG_DATA_HOME/privacylens (default ~/.local/share/privacylens)
//
// The PRIVACYLENS_DATA_DIR environment variable overrides the location.
func DataDir() (string, error) {
	d, err := Locate()
	if err != nil {
		return "", err
	}
	return ensure(d)
}

// Locate returns the data directory path without creating it. Use this when
// the path is needed for comparison only (e.g. the scanner excluding its own
// data from a scan), so that merely asking doesn't create the directory.
func Locate() (string, error) {
	if v := os.Getenv("PRIVACYLENS_DATA_DIR"); v != "" {
		return v, nil
	}
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			base = filepath.Join(home, "AppData", "Local")
		}
		return filepath.Join(base, "PrivacyLens"), nil
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Application Support", "PrivacyLens"), nil
	default:
		if x := os.Getenv("XDG_DATA_HOME"); x != "" {
			return filepath.Join(x, "privacylens"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".local", "share", "privacylens"), nil
	}
}

// ReportsDir returns <DataDir>/reports, where timestamped HTML/JSON reports
// are written.
func ReportsDir() (string, error) {
	return subdir("reports")
}

// FindingsLog returns <DataDir>/logs/findings.json — the append-only NDJSON
// event log a log shipper (e.g. a Wazuh agent) can tail.
func FindingsLog() (string, error) {
	d, err := subdir("logs")
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "findings.json"), nil
}

// SystemFindingsLog returns the machine-wide findings log that "privacylens
// install" registers for the SIEM agent (e.g. Wazuh) to tail:
//
//	Windows:  %ProgramData%\PrivacyLens\logs\findings.json
//	else:     /var/log/privacylens/findings.json
//
// The path is only resolved, never created: whether the caller may write
// there depends on how the machine was set up (the installer creates the
// directory as admin/root).
func SystemFindingsLog() string {
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "PrivacyLens", "logs", "findings.json")
	}
	return "/var/log/privacylens/findings.json"
}

func subdir(name string) (string, error) {
	d, err := DataDir()
	if err != nil {
		return "", err
	}
	return ensure(filepath.Join(d, name))
}

func ensure(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	return dir, nil
}
