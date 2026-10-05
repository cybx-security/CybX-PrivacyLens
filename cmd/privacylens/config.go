package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"unicode/utf16"
)

// fileConfig is the scan manifest (-config scan.json, or the
// PRIVACYLENS_CONFIG environment variable). Every field mirrors a CLI flag;
// flags given explicitly on the command line win over the file. Pointer
// fields distinguish "absent" from a real false/zero.
type fileConfig struct {
	Paths    []string `json:"paths"`
	Excludes []string `json:"excludes"`
	// ExcludeEmails suppresses Email Address findings for known-benign
	// addresses: exact ("info@x.com") or a whole domain ("@x.com").
	ExcludeEmails []string `json:"exclude_emails"`
	// Categories restricts the scan to these PII types (names as shown in
	// reports; case and punctuation are forgiven, so "ssn" and
	// "email-address" work too). Absent or empty means all types.
	Categories     []string `json:"categories"`
	MinConfidence  string   `json:"min_confidence"`
	MaxSizeMB      *int64   `json:"max_size_mb"`
	Workers        *int     `json:"workers"`
	MemoryBudgetMB *int64   `json:"memory_budget_mb"`
	ShowFull       *bool    `json:"show_full"`
	HTML           string   `json:"html"`
	JSON           string   `json:"json"`
	CSV            string   `json:"csv"`
	SyslogOut      string   `json:"syslog_out"`
	SyslogAddr     string   `json:"syslog_addr"`
	SyslogFormat   string   `json:"syslog_format"`
	IncludeCloud   *bool    `json:"include_cloud"`
	ScanAll        *bool    `json:"scan_all"`
	OCR            *bool    `json:"ocr"`
	Mail           *bool    `json:"mail"`
	Quiet          *bool    `json:"quiet"`
	Verbose        *bool    `json:"verbose"`
	NoFindingsLog  *bool    `json:"no_findings_log"`
}

// loadConfig reads and validates a manifest. Unknown keys are rejected so a
// typo like "pathes" fails loudly instead of silently scanning nothing.
func loadConfig(path string) (*fileConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read config: %w", err)
	}
	b = normalizeEncoding(b)
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var cfg fileConfig
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return &cfg, nil
}

// normalizeEncoding makes manifests written by Windows tools parseable:
// Windows PowerShell 5.1's `Set-Content -Encoding UTF8` prepends a UTF-8
// BOM, and `>` redirection writes UTF-16LE — both of which Go's JSON
// decoder rejects at the first byte. Strip a UTF-8 BOM; transcode UTF-16
// (either endianness, identified by its BOM) to UTF-8.
func normalizeEncoding(b []byte) []byte {
	if bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}) {
		return b[3:]
	}
	var little bool
	switch {
	case bytes.HasPrefix(b, []byte{0xFF, 0xFE}):
		little = true
	case bytes.HasPrefix(b, []byte{0xFE, 0xFF}):
		little = false
	default:
		return b
	}
	u := make([]uint16, 0, (len(b)-2)/2)
	for i := 2; i+1 < len(b); i += 2 {
		if little {
			u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
		} else {
			u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
		}
	}
	return []byte(string(utf16.Decode(u)))
}
