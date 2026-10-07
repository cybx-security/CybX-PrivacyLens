package report

import (
	"fmt"
	"strings"
)

// Params records the settings a scan was run with, so a report answers
// "what did this scan look for, and how?" alongside what it found. The
// paths scanned live on Report.Roots and masking on Report.Masked; every
// other knob is here. A nil Params on a Report means an older report that
// never recorded them.
type Params struct {
	// Source is where the scan was started from: "gui" or "cli".
	Source        string   `json:"source,omitempty"`
	Excludes      []string `json:"excludes,omitempty"`
	ExcludeEmails []string `json:"exclude_emails,omitempty"`
	MinConfidence string   `json:"min_confidence"`
	MaxSizeMB     int64    `json:"max_size_mb"`
	// Categories restricts the scan to these PII types; empty means all.
	Categories   []string `json:"categories,omitempty"`
	OCR          bool     `json:"ocr"`
	IncludeCloud bool     `json:"include_cloud"`
	ScanAll      bool     `json:"scan_all"`
	Mail         bool     `json:"mail"`
	// InsightsLog is whether findings were streamed to the findings log a
	// SIEM agent watches (the machine-wide one, or the per-user fallback).
	InsightsLog bool `json:"insights_log"`
}

// ParamLine is one human-readable "Label: Value" row describing a setting,
// worded for the HTML report and the GUI alike so the two never disagree.
type ParamLine struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// Lines describes the settings as label/value rows, in display order.
func (p *Params) Lines() []ParamLine {
	if p == nil {
		return nil
	}
	list := func(items []string, empty string) string {
		if len(items) == 0 {
			return empty
		}
		return strings.Join(items, ", ")
	}
	onOff := func(b bool, on, off string) string {
		if b {
			return on
		}
		return off
	}
	conf := map[string]string{
		"low":    "Low — report everything",
		"medium": "Medium and above",
		"high":   "High only",
	}[strings.ToLower(p.MinConfidence)]
	if conf == "" {
		conf = p.MinConfidence
	}
	size := fmt.Sprintf("%d MB", p.MaxSizeMB)
	if p.MaxSizeMB >= 1024 && p.MaxSizeMB%1024 == 0 {
		size = fmt.Sprintf("%d GB", p.MaxSizeMB/1024)
	}
	lines := []ParamLine{}
	if p.Source != "" {
		lines = append(lines, ParamLine{"Started from", map[string]string{"gui": "PrivacyLens window", "cli": "Command line"}[p.Source]})
		if lines[len(lines)-1].Value == "" {
			lines[len(lines)-1].Value = p.Source
		}
	}
	lines = append(lines,
		ParamLine{"PII types", list(p.Categories, "All types")},
		ParamLine{"Minimum confidence", conf},
		ParamLine{"Excluded patterns", list(p.Excludes, "None")},
		ParamLine{"Ignored emails", list(p.ExcludeEmails, "None")},
		ParamLine{"Max file size", size},
		ParamLine{"OCR", onOff(p.OCR, "On — scanned documents and images read with Tesseract", "Off — image-only documents listed as not searched")},
		ParamLine{"Cloud-only files", onOff(p.IncludeCloud, "Included — downloaded from OneDrive/iCloud as needed", "Skipped — listed as not searched")},
		ParamLine{"Built-in skip list", onOff(p.ScanAll, "Disabled — everything scanned, including AppData, caches, and the Recycle Bin", "Applied — AppData, caches, Recycle Bin, and node_modules skipped")},
		ParamLine{"Mail scan", onOff(p.Mail, "Yes — only Outlook mailboxes (.pst/.ost files and Outlook for Mac's message store), read message by message", "No")},
		ParamLine{"Insights findings log", onOff(p.InsightsLog, "On", "Off")},
	)
	return lines
}
