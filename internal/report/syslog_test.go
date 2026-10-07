package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rdataback/privacylens/internal/scanner"
)

func sampleReport(masked bool) *Report {
	return &Report{
		Tool:        "PrivacyLens",
		Version:     "0.2.0",
		GeneratedAt: time.Date(2026, 7, 2, 9, 0, 0, 0, time.UTC),
		Roots:       []string{"/data"},
		Masked:      masked,
		Findings: []scanner.Finding{{
			Path:       "/data/hr/pay=roll.csv",
			FileName:   "pay=roll.csv",
			Category:   "SSN",
			Confidence: "high",
			Line:       2,
			Match:      "219-09-9999",
			Context:    "Jane,219-09-9999,03/14/1985",
		}},
	}
}

func TestCEFLineEscapingAndMasking(t *testing.T) {
	lines, err := SyslogLines(sampleReport(true), "cef", "testhost", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 { // finding + scan_summary
		t.Fatalf("want 2 lines (finding + summary), got %d", len(lines))
	}
	l := lines[0]
	if !strings.HasPrefix(l, "<132>") { // local0.warning for high confidence
		t.Errorf("high finding should have PRI 132, got %q", l[:8])
	}
	if !strings.Contains(l, "CEF:0|CybX|PrivacyLens|0.2.0|ssn|PII detected: SSN|8|") {
		t.Errorf("CEF header wrong: %q", l)
	}
	if !strings.Contains(l, `filePath=/data/hr/pay\=roll.csv`) {
		t.Errorf("extension '=' must be escaped: %q", l)
	}
	if strings.Contains(l, "219-09-9999") {
		t.Errorf("masked report must not contain the raw SSN: %q", l)
	}
	if !strings.Contains(l, "cs3=***-**-9999") {
		t.Errorf("masked match missing: %q", l)
	}
}

// TestCEFFileLinesHaveNoPRI: CEF written to a file (EventWriter) must start
// with the plain RFC 3164 header, never a <PRI> tag. A log shipper tails the
// file verbatim, and a leading "<133>" defeats Wazuh's pre-decoder so no
// event ever reaches the PrivacyLens decoders. PRI belongs to network
// transport only (TestCEFLineEscapingAndMasking covers that path).
func TestCEFFileLinesHaveNoPRI(t *testing.T) {
	var buf bytes.Buffer
	ew, err := NewEventWriter(&buf, "cef", "PrivacyLens", "0.8.1", true, true)
	if err != nil {
		t.Fatal(err)
	}
	ew.Finding(sampleReport(true).Findings[0])
	line := strings.TrimSpace(buf.String())
	if strings.HasPrefix(line, "<") {
		t.Errorf("file CEF line must not carry a <PRI> tag: %q", line)
	}
	if !strings.Contains(line, " privacylens: CEF:0|CybX|PrivacyLens|") {
		t.Errorf("file CEF line must keep the syslog header for program_name pre-decoding: %q", line)
	}
}

func TestJSONLinesAreBareNDJSON(t *testing.T) {
	lines, err := SyslogLines(sampleReport(false), "json", "testhost", false)
	if err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("file-mode json line must be pure JSON: %v (%q)", err, lines[0])
	}
	if rec["category_id"] != "ssn" || rec["category"] != "SSN" {
		t.Errorf("category fields wrong: %v", rec)
	}
	if rec["match"] != "219-09-9999" {
		t.Errorf("unmasked report should carry the full value, got %v", rec["match"])
	}
}

func TestJSONLinesLeadWithToolAndEventType(t *testing.T) {
	rep := sampleReport(true)
	rep.Stats.NeedOCR = []string{"/data/scans/intake_form.pdf"}
	lines, err := SyslogLines(rep, "json", "testhost", false)
	if err != nil {
		t.Fatal(err)
	}
	wantTypes := []string{"finding", "needs_ocr", "scan_summary"}
	for i, l := range lines {
		prefix := `{"tool":"PrivacyLens","privacylens_event":"` + wantTypes[i] + `"`
		if !strings.HasPrefix(l, prefix) {
			t.Errorf("line %d should start with %s, got %q", i, prefix, l)
		}
		// The key must stay "privacylens_event" — a literal "event_type"
		// (combined with "timestamp") gets captured by Wazuh's stock
		// Suricata base rule 86600 before PrivacyLens rules can match.
		if strings.Contains(l, `"event_type"`) {
			t.Errorf("line %d must not carry an event_type key (Suricata rule collision): %q", i, l)
		}
	}
}

func TestNeedsOCRAndSummaryEvents(t *testing.T) {
	rep := sampleReport(true)
	rep.Stats.FilesScanned = 6
	rep.Stats.FilesNeedOCR = 1
	rep.Stats.FilesCloud = 4
	rep.Stats.NeedOCR = []string{"/data/scans/intake_form.pdf"}

	// JSON, file mode: finding + needs_ocr + scan_summary, all bare NDJSON.
	lines, err := SyslogLines(rep, "json", "testhost", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 3 {
		t.Fatalf("want 3 lines (finding, needs_ocr, summary), got %d", len(lines))
	}
	var ocr, summary map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &ocr); err != nil {
		t.Fatal(err)
	}
	if ocr["privacylens_event"] != "needs_ocr" || ocr["path"] != "/data/scans/intake_form.pdf" {
		t.Errorf("needs_ocr event wrong: %v", ocr)
	}
	if err := json.Unmarshal([]byte(lines[2]), &summary); err != nil {
		t.Fatal(err)
	}
	if summary["privacylens_event"] != "scan_summary" ||
		summary["files_need_ocr"] != float64(1) || summary["findings"] != float64(1) ||
		summary["files_scanned"] != float64(6) || summary["files_cloud_skipped"] != float64(4) {
		t.Errorf("scan_summary event wrong: %v", summary)
	}
	var finding map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &finding); err != nil {
		t.Fatal(err)
	}
	if finding["privacylens_event"] != "finding" {
		t.Errorf("finding event should carry privacylens_event=finding: %v", finding)
	}

	// CEF mode: signature IDs are stable for SIEM rules.
	cefLines, err := SyslogLines(rep, "cef", "testhost", true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cefLines[1], "|needs-ocr|Document not searched - needs OCR|5|") {
		t.Errorf("needs-ocr CEF wrong: %q", cefLines[1])
	}
	if !strings.Contains(cefLines[2], "|scan-summary|PII scan completed|3|") ||
		!strings.Contains(cefLines[2], "cn3Label=filesNeedOcr cn3=1") ||
		!strings.Contains(cefLines[2], "cloud-skipped 4") {
		t.Errorf("scan-summary CEF wrong: %q", cefLines[2])
	}
}

func TestCategorySlug(t *testing.T) {
	cases := map[string]string{
		"SSN":                           "ssn",
		"Credit Card":                   "credit-card",
		"Medical Record Number (HIPAA)": "medical-record-number-hipaa",
		"Driver's License":              "driver-s-license",
	}
	for in, want := range cases {
		if got := categorySlug(in); got != want {
			t.Errorf("categorySlug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSendSyslogRejectsBadAddress(t *testing.T) {
	if err := SendSyslog("wazuh.local:514", []string{"x"}); err == nil {
		t.Error("address without scheme should be rejected")
	}
}

// TestMailFindingFields: mail-store findings carry folder/subject in both
// JSON events and CEF extensions, and masking covers a subject that
// contains the matched value.
func TestMailFindingFields(t *testing.T) {
	rep := sampleReport(true)
	rep.Findings = []scanner.Finding{{
		Path: "C:\\Users\\t\\archive.pst", FileName: "archive.pst",
		Category: "SSN", Confidence: "high", Line: 7,
		Folder: "Inbox", Subject: "ssn 219-09-9999 for onboarding", Date: "2026-10-07 09:15", From: "HR <hr@example.com>",
		Match: "219-09-9999", Context: "his ssn 219-09-9999 attached",
	}}

	lines, err := SyslogLines(rep, "json", "testhost", false)
	if err != nil {
		t.Fatal(err)
	}
	var ev map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatal(err)
	}
	if ev["folder"] != "Inbox" {
		t.Errorf("folder missing from JSON event: %v", ev)
	}
	subj, _ := ev["subject"].(string)
	if strings.Contains(subj, "219-09-9999") {
		t.Errorf("masked event leaked the match via the subject: %q", subj)
	}
	if subj == "" {
		t.Errorf("subject missing from JSON event: %v", ev)
	}

	cefLines, err := SyslogLines(rep, "cef", "testhost", true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cefLines[0], "cs4Label=mailFolder cs4=Inbox") ||
		!strings.Contains(cefLines[0], "cs5Label=mailSubject") || !strings.Contains(cefLines[0], "cs6Label=mailDate cs6=2026-10-07 09:15") ||
		!strings.Contains(cefLines[0], "suser=") {
		t.Errorf("CEF mail fields missing: %q", cefLines[0])
	}
}
