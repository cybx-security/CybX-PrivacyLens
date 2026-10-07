package report

import (
	"bytes"
	"strings"
	"testing"
)

func TestHTMLReportShowsScanSettings(t *testing.T) {
	rep := sampleReport(true)
	rep.Params = &Params{
		Source: "gui", Excludes: []string{"*.bak", "node_modules"}, MinConfidence: "medium",
		MaxSizeMB: 50 * 1024, Categories: []string{"SSN", "Credit Card"}, Mail: true, InsightsLog: true,
	}
	var buf bytes.Buffer
	if err := WriteHTML(&buf, rep); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"Scan settings", "*.bak, node_modules", "Medium and above", "50 GB", "SSN, Credit Card", "Outlook mailboxes", "PrivacyLens window", "/data"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}

	// An older report with no params still renders, and says so.
	rep.Params = nil
	buf.Reset()
	if err := WriteHTML(&buf, rep); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Not recorded") {
		t.Error("report without params should say settings were not recorded")
	}
}

// Coverage warnings and auto-searched Outlook locations are shown in the
// HTML report and on the console.
func TestReportShowsWarningsAndMailRoots(t *testing.T) {
	rep := sampleReport(true)
	rep.Stats.Warnings = []string{"Your Outlook mailbox was NOT searched: test warning"}
	rep.Stats.MailRoots = []string{"/Users/x/Library/Group Containers/UBF8T346G9.Office/Outlook/Outlook 15 Profiles"}
	var buf bytes.Buffer
	if err := WriteHTML(&buf, rep); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "test warning") || !strings.Contains(buf.String(), "Also searched") {
		t.Error("HTML report missing the warning or the auto-searched location")
	}
	buf.Reset()
	PrintConsole(&buf, rep, false)
	if !strings.Contains(buf.String(), "WARNING: Your Outlook mailbox was NOT searched") || !strings.Contains(buf.String(), "Also searched Outlook") {
		t.Errorf("console output missing warning or mail roots:\n%s", buf.String())
	}
}

func TestParamsLinesNil(t *testing.T) {
	var p *Params
	if p.Lines() != nil {
		t.Error("nil params should give no lines")
	}
}
