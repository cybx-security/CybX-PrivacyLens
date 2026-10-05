package main

import (
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scan.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfig(t *testing.T) {
	path := writeConfig(t, `{
		"paths": ["C:\\Users", "/data"],
		"excludes": ["node_modules", "*.bak"],
		"min_confidence": "medium",
		"max_size_mb": 100,
		"show_full": false,
		"syslog_addr": "udp://wazuh:514"
	}`)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Paths) != 2 || cfg.Paths[0] != `C:\Users` {
		t.Errorf("paths wrong: %v", cfg.Paths)
	}
	if cfg.MinConfidence != "medium" || *cfg.MaxSizeMB != 100 || *cfg.ShowFull {
		t.Errorf("scalar fields wrong: %+v", cfg)
	}
	if cfg.SyslogAddr != "udp://wazuh:514" {
		t.Errorf("syslog_addr wrong: %q", cfg.SyslogAddr)
	}
	if cfg.Quiet != nil {
		t.Error("absent bool must stay nil so it cannot override a flag")
	}
}

// PowerShell 5.1's Set-Content -Encoding UTF8 prepends a UTF-8 BOM (Notepad
// can too), and `>` redirection writes UTF-16 with BOM. Manifests written by
// any of them must load.
func TestLoadConfigWindowsEncodings(t *testing.T) {
	const manifest = `{"paths": ["C:\\Users"], "min_confidence": "medium"}`
	units := utf16.Encode([]rune(manifest))
	le := []byte{0xFF, 0xFE}
	be := []byte{0xFE, 0xFF}
	for _, u := range units {
		le = append(le, byte(u), byte(u>>8))
		be = append(be, byte(u>>8), byte(u))
	}
	cases := map[string]string{
		"utf8-bom": "\xEF\xBB\xBF" + manifest,
		"utf16-le": string(le),
		"utf16-be": string(be),
	}
	for name, content := range cases {
		cfg, err := loadConfig(writeConfig(t, content))
		if err != nil {
			t.Errorf("%s manifest should load: %v", name, err)
			continue
		}
		if len(cfg.Paths) != 1 || cfg.Paths[0] != `C:\Users` || cfg.MinConfidence != "medium" {
			t.Errorf("%s manifest decoded wrong: %+v", name, cfg)
		}
	}
}

func TestLoadConfigRejectsUnknownKeys(t *testing.T) {
	path := writeConfig(t, `{"pathes": ["/data"]}`)
	if _, err := loadConfig(path); err == nil {
		t.Error("misspelled key should be rejected, not ignored")
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := loadConfig("/nonexistent/scan.json"); err == nil {
		t.Error("missing file should error")
	}
}

func TestLoadConfigCategories(t *testing.T) {
	path := writeConfig(t, `{"paths": ["/data"], "categories": ["SSN", "email-address"]}`)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Categories) != 2 || cfg.Categories[0] != "SSN" || cfg.Categories[1] != "email-address" {
		t.Errorf("categories wrong: %v", cfg.Categories)
	}
}
