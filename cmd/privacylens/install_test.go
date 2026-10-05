package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDownloadVerified(t *testing.T) {
	payload := []byte("official artifact bytes")
	sum := sha256.Sum256(payload)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "artifact")
	if err := downloadVerified(srv.URL, hex.EncodeToString(sum[:]), dst); err != nil {
		t.Fatalf("valid checksum should succeed: %v", err)
	}
	got, _ := os.ReadFile(dst)
	if !bytes.Equal(got, payload) {
		t.Error("downloaded content wrong")
	}

	bad := filepath.Join(t.TempDir(), "bad")
	err := downloadVerified(srv.URL, "00000000000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeef", bad)
	if err == nil {
		t.Fatal("checksum mismatch must be rejected")
	}
	if _, statErr := os.Stat(bad); !os.IsNotExist(statErr) {
		t.Error("mismatched download must be deleted, not left on disk")
	}
}

func TestExtractZipBlocksSlip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range map[string]string{
		"poppler-26.0/Library/bin/pdftoppm.exe": "binary",
		"../evil.txt":                           "escape attempt",
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(content))
	}
	zw.Close()
	zipPath := filepath.Join(t.TempDir(), "a.zip")
	if err := os.WriteFile(zipPath, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(t.TempDir(), "out")
	if err := extractZip(zipPath, dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "poppler-26.0", "Library", "bin", "pdftoppm.exe")); err != nil {
		t.Error("nested file should have been extracted")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dest), "evil.txt")); !os.IsNotExist(err) {
		t.Error("zip-slip entry must not escape the destination")
	}
}

// TestWriteManifestRoundTrips: the installer's generated manifest must
// always pass the scanner's own strict manifest parser (unknown keys and
// bad JSON are rejected), with and without OCR enabled.
func TestWriteManifestRoundTrips(t *testing.T) {
	for _, ocr := range []bool{true, false} {
		dir := t.TempDir()
		p := installPaths{
			manifest: filepath.Join(dir, "scan.json"),
			logPath:  filepath.Join(dir, "logs", "findings.json"),
		}
		if err := writeManifest(p, ocr); err != nil {
			t.Fatalf("ocr=%v: %v", ocr, err)
		}
		cfg, err := loadConfig(p.manifest)
		if err != nil {
			t.Fatalf("ocr=%v: generated manifest does not load: %v", ocr, err)
		}
		if cfg.OCR == nil || *cfg.OCR != ocr {
			t.Errorf("ocr=%v: manifest ocr field wrong: %+v", ocr, cfg.OCR)
		}
		if cfg.SyslogOut != p.logPath || cfg.SyslogFormat != "json" {
			t.Errorf("ocr=%v: syslog fields wrong: %q %q", ocr, cfg.SyslogOut, cfg.SyslogFormat)
		}
		if len(cfg.Paths) == 0 || cfg.MinConfidence != "medium" {
			t.Errorf("ocr=%v: defaults wrong: %+v", ocr, cfg)
		}
	}
}

// tempInstall builds an install layout entirely under a temp directory and
// stubs the platform scheduler, so the real install/uninstall flow can run
// in a test without touching this machine.
func tempInstall(t *testing.T) installPaths {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the Windows flow edits machine-wide permissions and the registry; covered by the CI installer job")
	}
	root := t.TempDir()
	p := installPaths{
		binDir:       filepath.Join(root, "bin"),
		binPath:      filepath.Join(root, "bin", "privacylens"),
		guiPath:      filepath.Join(root, "bin", "privacylens-gui"),
		etcDir:       filepath.Join(root, "etc"),
		manifest:     filepath.Join(root, "etc", "scan.json"),
		logDir:       filepath.Join(root, "log"),
		logPath:      filepath.Join(root, "log", "findings.json"),
		desktopEntry: filepath.Join(root, "privacylens.desktop"),
	}
	scheduled := false
	origReg, origRem, origQ := registerScheduleFn, removeScheduleFn, scheduleRegisteredFn
	registerScheduleFn = func(installPaths) error { scheduled = true; return nil }
	removeScheduleFn = func(func(string, error)) { scheduled = false }
	scheduleRegisteredFn = func() bool { return scheduled }
	t.Cleanup(func() { registerScheduleFn, removeScheduleFn, scheduleRegisteredFn = origReg, origRem, origQ })
	return p
}

func TestInstallStatusUninstall(t *testing.T) {
	p := tempInstall(t)

	var before bytes.Buffer
	if code := status(p, &before); code == exitClean {
		t.Errorf("status before install should report problems:\n%s", before.String())
	}

	if code := install(p, installOptions{noOCR: true}); code != exitClean {
		t.Fatalf("install exit code = %d", code)
	}
	for _, f := range []string{p.binPath, p.manifest, p.logPath} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("install did not create %s: %v", f, err)
		}
	}
	if fi, err := os.Stat(p.binPath); err == nil && fi.Mode().Perm()&0o111 == 0 {
		t.Error("installed program is not executable")
	}

	// A re-install must keep an edited manifest.
	custom := []byte(`{"paths": ["` + filepath.ToSlash(p.etcDir) + `"], "quiet": true}`)
	if err := os.WriteFile(p.manifest, custom, 0o644); err != nil {
		t.Fatal(err)
	}
	if code := install(p, installOptions{noOCR: true}); code != exitClean {
		t.Fatalf("re-install exit code = %d", code)
	}
	if got, _ := os.ReadFile(p.manifest); !bytes.Equal(got, custom) {
		t.Error("re-install overwrote an existing manifest")
	}

	var after bytes.Buffer
	if code := status(p, &after); code != exitClean {
		t.Errorf("status after install should be healthy:\n%s", after.String())
	}

	// Default uninstall removes the program but keeps the records.
	uninstall(p, false)
	if _, err := os.Stat(p.binPath); !os.IsNotExist(err) {
		t.Error("uninstall left the program behind")
	}
	for _, f := range []string{p.manifest, p.logPath} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("uninstall without -purge removed %s", f)
		}
	}
	uninstall(p, true)
	for _, d := range []string{p.etcDir, p.logDir} {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Errorf("uninstall -purge left %s behind", d)
		}
	}
}

func TestInstallGUIBundle(t *testing.T) {
	src := filepath.Join(t.TempDir(), "PrivacyLens.app")
	exe := filepath.Join(src, "Contents", "MacOS", "PrivacyLens")
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "Contents", "Info.plist"), []byte("<plist/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "Applications", "PrivacyLens.app")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // twice: an upgrade replaces the old bundle
		if err := installGUI(src, dst); err != nil {
			t.Fatal(err)
		}
	}
	fi, err := os.Stat(filepath.Join(dst, "Contents", "MacOS", "PrivacyLens"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o111 == 0 {
		t.Error("bundle executable lost its execute permission")
	}
}

func TestReadLastScan(t *testing.T) {
	log := filepath.Join(t.TempDir(), "findings.json")
	if s, err := readLastScan(log); s != nil || !os.IsNotExist(err) {
		t.Fatalf("missing log: got %+v, %v", s, err)
	}
	content := `{"tool":"PrivacyLens","privacylens_event":"scan_summary","version":"0.9.5","timestamp":"2026-09-27T02:04:00-04:00","findings":3,"files_scanned":100}
{"tool":"PrivacyLens","privacylens_event":"finding","version":"0.9.6","timestamp":"2026-10-04T02:01:00-04:00"}
{"tool":"PrivacyLens","privacylens_event":"scan_summary","version":"0.9.6","timestamp":"2026-10-04T02:05:00-04:00","findings":7,"files_scanned":4210}
{"tool":"PrivacyLens","privacylens_event":"finding","version":"0.9.6","timestamp":"2026-10-05T09:00:00-04:00"}
`
	if err := os.WriteFile(log, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := readLastScan(log)
	if err != nil || s == nil || s.Findings != 7 || s.FilesScanned != 4210 {
		t.Fatalf("got %+v, %v; want the newest summary (7 findings, 4210 files)", s, err)
	}
}

func TestCheckAgentConfigs(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "ossec.conf")
	const logPath = `C:\ProgramData\PrivacyLens\logs\findings.json`

	if a := checkAgentConfigs([]string{conf}, logPath); a.found {
		t.Errorf("no config: %+v", a)
	}
	os.WriteFile(conf, []byte("<ossec_config></ossec_config>"), 0o644)
	if a := checkAgentConfigs([]string{conf}, logPath); !a.found || a.watching {
		t.Errorf("config without the log: %+v", a)
	}
	// Case and slash direction differ from the canonical path on purpose.
	os.WriteFile(conf, []byte(`<localfile><location>c:/programdata/privacylens/LOGS/findings.json</location></localfile>`), 0o644)
	if a := checkAgentConfigs([]string{conf}, logPath); !a.watching {
		t.Errorf("config with the log: %+v", a)
	}
}

// The Installed-apps entry is built by a pure function so its shape can be
// checked on any platform.
func TestUninstallEntryValues(t *testing.T) {
	p := installPaths{binDir: `C:\Program Files\PrivacyLens`, binPath: `C:\Program Files\PrivacyLens\privacylens.exe`}
	vals := map[string]string{}
	for _, v := range uninstallEntryValues(p) {
		vals[v.name] = v.data
	}
	if vals["UninstallString"] != `"C:\Program Files\PrivacyLens\privacylens.exe" uninstall -pause` {
		t.Errorf("UninstallString = %s", vals["UninstallString"])
	}
	if vals["DisplayName"] != toolName || vals["DisplayVersion"] != version || vals["Publisher"] != "CybX" {
		t.Errorf("uninstall entry values wrong: %v", vals)
	}
}
