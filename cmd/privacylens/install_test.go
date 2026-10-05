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
