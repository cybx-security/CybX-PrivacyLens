package report

import (
	"os"
	"strings"
	"testing"

	"github.com/rdataback/privacylens/internal/scanner"
)

func TestSaveDefaults(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PRIVACYLENS_DATA_DIR", dir)

	rep := sampleReport(true)
	saved, err := SaveDefaults(rep)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{saved.HTML, saved.JSON} {
		if !strings.HasPrefix(p, dir) {
			t.Errorf("saved path %q should be under the data dir %q", p, dir)
		}
		if fi, err := os.Stat(p); err != nil || fi.Size() == 0 {
			t.Errorf("saved file %q missing or empty: %v", p, err)
		}
	}

	// The report must honor masking.
	html, err := os.ReadFile(saved.HTML)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(html), "219-09-9999") {
		t.Error("auto-saved report must not contain the raw SSN when masked")
	}
}

func TestFindingsStreamAppendsAcrossRuns(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PRIVACYLENS_DATA_DIR", dir)
	rep := sampleReport(true)

	run := func() string {
		ew, logPath, err := OpenFindingsStream(rep.Tool, rep.Version, rep.Masked)
		if err != nil {
			t.Fatal(err)
		}
		ew.Findings(rep.Findings)
		if err := ew.Finish(rep); err != nil {
			t.Fatal(err)
		}
		return logPath
	}

	logPath := run()
	before, _ := os.ReadFile(logPath)
	// A second run must APPEND to the findings log, never truncate it: the
	// Wazuh agent tracks a byte offset, and only appended bytes are
	// guaranteed to be seen exactly once (a replaced file larger than the
	// old offset silently skips events).
	run()
	after, _ := os.ReadFile(logPath)
	if len(after) != 2*len(before) || len(before) == 0 {
		t.Errorf("findings log should double across two identical runs: %d -> %d bytes", len(before), len(after))
	}

	// Streamed lines must be masked, flat NDJSON with the standard lead.
	for _, line := range strings.Split(strings.TrimSpace(string(before)), "\n") {
		if !strings.HasPrefix(line, `{"tool":"PrivacyLens","privacylens_event":"`) {
			t.Errorf("streamed line missing standard lead: %q", line)
		}
		if strings.Contains(line, "219-09-9999") {
			t.Errorf("streamed line must be masked: %q", line)
		}
	}
}

// The HTML report renders one document block per file, not per finding.
func TestWriteHTMLGroupsByDocument(t *testing.T) {
	r := &Report{Tool: "PrivacyLens", Version: "test", Masked: true,
		Findings: []scanner.Finding{
			{Path: `C:\a.pdf`, Category: "SSN", Match: "***-**-1234", Context: "ssn ***-**-1234", Confidence: "high", Line: 1},
			{Path: `C:\a.pdf`, Category: "Phone Number", Match: "***-***-0629", Context: "tel ***-***-0629", Confidence: "high", Line: 2},
			{Path: `C:\b.txt`, Category: "Email Address", Match: "a**@x.com", Context: "a**@x.com", Confidence: "medium", Line: 5},
		}}
	var buf strings.Builder
	if err := WriteHTML(&buf, r); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	if got := strings.Count(html, `class="doc-head"`); got != 2 {
		t.Errorf("document blocks = %d, want 2", got)
	}
	for _, want := range []string{"SSN ×1", "Phone Number ×1", "Email Address ×1"} {
		if !strings.Contains(html, want) {
			t.Errorf("missing category chip %q", want)
		}
	}
}
