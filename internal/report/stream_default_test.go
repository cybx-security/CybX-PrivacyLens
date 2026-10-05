package report

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// OpenDefaultFindingsStream: every scan streams somewhere, preferring the
// machine-wide Insights log whenever the installer set it up.
func TestOpenDefaultStream(t *testing.T) {
	t.Run("system log used when its directory exists", func(t *testing.T) {
		sysDir := t.TempDir()
		sysPath := filepath.Join(sysDir, "findings.json")
		t.Setenv("PRIVACYLENS_DATA_DIR", t.TempDir())
		ew, path, warn := OpenDefaultFindingsStream(sysPath, "PrivacyLens", "test", true)
		if ew == nil || path != sysPath || warn != "" {
			t.Fatalf("got path=%q warn=%q, want system log with no warning", path, warn)
		}
		ew.Abort()
	})

	t.Run("per-user log, silently, when system dir is absent", func(t *testing.T) {
		userDir := t.TempDir()
		t.Setenv("PRIVACYLENS_DATA_DIR", userDir)
		ew, path, warn := OpenDefaultFindingsStream(filepath.Join(t.TempDir(), "nonexistent", "findings.json"), "PrivacyLens", "test", true)
		if ew == nil || warn != "" {
			t.Fatalf("got warn=%q, want silent per-user fallback", warn)
		}
		if !strings.HasPrefix(path, userDir) {
			t.Errorf("path = %q, want under %q", path, userDir)
		}
		ew.Abort()
	})

	t.Run("loud fallback when system dir exists but is unwritable", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("needs POSIX permissions and a non-root user")
		}
		sysDir := t.TempDir()
		if err := os.Chmod(sysDir, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(sysDir, 0o755) })
		userDir := t.TempDir()
		t.Setenv("PRIVACYLENS_DATA_DIR", userDir)
		ew, path, warn := OpenDefaultFindingsStream(filepath.Join(sysDir, "findings.json"), "PrivacyLens", "test", true)
		if ew == nil || !strings.HasPrefix(path, userDir) {
			t.Fatalf("got path=%q, want per-user fallback", path)
		}
		if !strings.Contains(warn, "Insights will NOT see this scan") {
			t.Errorf("warn = %q, want loud Insights warning", warn)
		}
		ew.Abort()
	})
}
