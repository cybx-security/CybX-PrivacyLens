package scanner

import (
	"context"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/rdataback/privacylens/internal/detect"
	"github.com/rdataback/privacylens/internal/extract"
)

func TestScanContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := ScanContext(ctx, []string{t.TempDir()}, Options{Workers: 1, MaxSizeBytes: 1 << 20})
	if err != context.Canceled {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

func TestByteLimiterCancellation(t *testing.T) {
	l := newByteLimiter(1 << 20)
	release, err := l.acquire(context.Background(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := l.acquire(ctx, 1<<20); err != context.Canceled {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

// writeFile creates path (and parents) with the given content.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestScanSkipsOwnDataDir plants a fake saved report inside the PrivacyLens
// data directory within the scan root: the scan must not re-report the PII
// in it, while still finding PII in a sibling file.
func TestScanSkipsOwnDataDir(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "PrivacyLens")
	t.Setenv("PRIVACYLENS_DATA_DIR", dataDir)

	writeFile(t, filepath.Join(dataDir, "reports", "old-report.json"), "ssn 123-45-6789")
	writeFile(t, filepath.Join(root, "notes.txt"), "ssn 123-45-6789")

	findings, _, err := Scan([]string{root}, Options{MaxSizeBytes: 1 << 20, Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings from notes.txt, got none")
	}
	for _, f := range findings {
		if strings.Contains(f.Path, dataDir) {
			t.Errorf("finding from own data dir should have been skipped: %s", f.Path)
		}
	}
}

// TestBuiltinSkipDirs: AppData-style directories are skipped during walks
// by default, scanned with ScanAll, and always scanned as an explicit root.
func TestBuiltinSkipDirs(t *testing.T) {
	root := t.TempDir()
	appData := filepath.Join(root, "AppData")
	writeFile(t, filepath.Join(appData, "Local", "cache.txt"), "ssn 123-45-6789")
	writeFile(t, filepath.Join(root, "notes.txt"), "ssn 123-45-6789")
	opts := Options{MaxSizeBytes: 1 << 20, Workers: 2}

	findings, _, err := Scan([]string{root}, opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if strings.Contains(f.Path, "AppData") {
			t.Errorf("AppData should be skipped by default: %s", f.Path)
		}
	}
	if len(findings) == 0 {
		t.Error("notes.txt outside AppData should still be scanned")
	}

	opts.ScanAll = true
	findings, _, err = Scan([]string{root}, opts)
	if err != nil {
		t.Fatal(err)
	}
	inAppData := 0
	for _, f := range findings {
		if strings.Contains(f.Path, "AppData") {
			inAppData++
		}
	}
	if inAppData == 0 {
		t.Error("ScanAll should scan AppData")
	}

	opts.ScanAll = false
	findings, _, err = Scan([]string{appData}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Error("an explicit root at AppData should still be scanned")
	}
}

// TestLocator: paged text (OCR'd PDFs, pages joined with \f) maps offsets
// to page + line-within-page; unpaged text keeps document line numbers.
func TestLocator(t *testing.T) {
	text := "a\nb ssn1\nc\fpage2 first\nssn2 here\n\fssn3"
	l := newLocator(true)
	cases := []struct {
		offset     int
		line, page int
	}{
		{strings.Index(text, "ssn1"), 2, 1},
		{strings.Index(text, "ssn2"), 2, 2},
		{strings.Index(text, "ssn3"), 1, 3},
	}
	for _, c := range cases {
		line, page := l.advance(text, c.offset)
		if line != c.line || page != c.page {
			t.Errorf("offset %d: got line %d page %d, want line %d page %d",
				c.offset, line, page, c.line, c.page)
		}
	}

	l = newLocator(false)
	line, page := l.advance(text, strings.Index(text, "ssn2"))
	if page != 0 || line != 4 {
		t.Errorf("unpaged: got line %d page %d, want line 4 page 0", line, page)
	}
}

// contextSnippetReference is the pre-optimization implementation, with
// unbounded line-boundary scans. The bounded version must produce identical
// snippets.
func contextSnippetReference(text string, m detect.Match) string {
	lineStart := strings.LastIndexByte(text[:m.Start], '\n') + 1
	lineEnd := strings.IndexByte(text[m.End:], '\n')
	if lineEnd < 0 {
		lineEnd = len(text)
	} else {
		lineEnd += m.End
	}
	start, end := lineStart, lineEnd
	prefix, suffix := "", ""
	if m.Start-start > 60 {
		start = m.Start - 60
		prefix = "…"
	}
	if end-m.End > 60 {
		end = m.End + 60
		suffix = "…"
	}
	snippet := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\t' || r < 32 {
			return ' '
		}
		return r
	}, text[start:end])
	return prefix + strings.TrimSpace(snippet) + suffix
}

func TestContextSnippetMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	alphabets := []string{"ab \ncd\n", "abcdef ", "\n\nab\n", "x"}
	for _, alpha := range alphabets {
		for trial := 0; trial < 500; trial++ {
			n := 1 + rng.Intn(400)
			var sb strings.Builder
			for i := 0; i < n; i++ {
				sb.WriteByte(alpha[rng.Intn(len(alpha))])
			}
			text := sb.String()
			start := rng.Intn(len(text) + 1)
			m := detect.Match{Start: start, End: start + rng.Intn(len(text)-start+1)}
			got, want := contextSnippet(text, m), contextSnippetReference(text, m)
			if got != want {
				t.Fatalf("snippet mismatch (alpha %q, len %d, start %d, end %d):\n got %q\nwant %q",
					alpha, len(text), m.Start, m.End, got, want)
			}
		}
	}
}

// TestScanExplicitDataDirRootStillScans: pointing a scan root directly at
// the data directory is a deliberate request and must still work.
func TestScanExplicitDataDirRootStillScans(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "PrivacyLens")
	t.Setenv("PRIVACYLENS_DATA_DIR", dataDir)

	writeFile(t, filepath.Join(dataDir, "reports", "old-report.json"), "ssn 123-45-6789")

	findings, _, err := Scan([]string{dataDir}, Options{MaxSizeBytes: 1 << 20, Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Error("explicitly scanning the data dir should still produce findings")
	}
}

// TestWalkableType: entries whose type can't be read safely (links, devices,
// pipes, sockets) are dropped, but ModeIrregular passes — on Windows since
// Go 1.23 every OneDrive Files On-Demand placeholder reports as irregular,
// and requiring IsRegular silently dropped them all before the
// cloud-placeholder check could run.
func TestWalkableType(t *testing.T) {
	cases := []struct {
		mode fs.FileMode
		want bool
	}{
		{0, true}, // regular
		{fs.ModeIrregular, true},
		{fs.ModeSymlink, false},
		{fs.ModeDevice, false},
		{fs.ModeDevice | fs.ModeCharDevice, false},
		{fs.ModeNamedPipe, false},
		{fs.ModeSocket, false},
	}
	for _, c := range cases {
		if got := walkableType(c.mode); got != c.want {
			t.Errorf("walkableType(%v) = %v, want %v", c.mode, got, c.want)
		}
	}
}

// TestScanFollowsSymlinkRoot: a root that is itself a symlink (Parallels
// shared folders on Windows are junctions) must be resolved and walked, not
// silently produce zero files.
func TestScanFollowsSymlinkRoot(t *testing.T) {
	real := t.TempDir()
	writeFile(t, filepath.Join(real, "sub", "notes.txt"), "ssn 123-45-6789")

	link := filepath.Join(t.TempDir(), "link-root")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	findings, stats, err := Scan([]string{link}, Options{MaxSizeBytes: 1 << 20, Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	if stats.FilesScanned == 0 || len(findings) == 0 {
		t.Fatalf("symlink root walked nothing: scanned=%d findings=%d", stats.FilesScanned, len(findings))
	}
}

// TestMailOnlyScan: a targeted mail scan opens only .pst/.ost files, walks
// otherwise-pruned dirs (AppData holds the live .ost), tags findings with
// folder/subject, and keeps partial results when a store is half-corrupt.
func TestMailOnlyScan(t *testing.T) {
	noOutlookLocations(t)
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "notes.txt"), "ssn 123-45-6789")
	writeFile(t, filepath.Join(root, "AppData", "Local", "Microsoft", "Outlook", "cache.ost"), "not a real store")
	writeFile(t, filepath.Join(root, "archive.pst"), "not a real store")
	// Outlook for Mac keeps one MIME file per message; read for real.
	macMsg := filepath.Join(root, "Library", "Group Containers", "UBF8T346G9.Office", "Outlook",
		"Outlook 15 Profiles", "Main Profile", "Data", "Message Sources", "0", "x_7.olk15MsgSource")
	writeFile(t, macMsg, "From: a@b.com\r\nSubject: payroll\r\nContent-Type: text/plain\r\n\r\nher ssn 219-09-9999\r\n")

	stub := func(path string) ([]extract.MailItem, error) {
		if extract.IsMessageSource(path) {
			return extract.ReadMailStore(path)
		}
		if strings.HasSuffix(path, ".ost") {
			return []extract.MailItem{
				{Folder: "Inbox", Subject: "re: onboarding", Index: 3, Text: "his ssn is 123-45-6789 thanks"},
			}, nil
		}
		// Partially corrupt store: one readable item plus an error.
		return []extract.MailItem{
			{Folder: "Sent", Subject: "card", Index: 1, Text: "card 4111 1111 1111 1111"},
		}, errFakeCorrupt
	}

	findings, stats, err := Scan([]string{root}, Options{
		MaxSizeBytes: 1 << 20, Workers: 2, MailOnly: true, mailRead: stub,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.FilesScanned != 3 {
		t.Errorf("want 3 mail stores scanned, got %d (stats %+v)", stats.FilesScanned, stats)
	}
	var sawMacSSN bool
	for _, f := range findings {
		if f.Path == macMsg {
			sawMacSSN = sawMacSSN || f.Category == "SSN"
			if f.Folder != "Outlook for Mac — Main Profile" || f.Subject != "payroll" || f.Line != 1 {
				t.Errorf("Mac message finding location wrong: %+v", f)
			}
		}
	}
	if !sawMacSSN {
		t.Error("expected an SSN finding from the Outlook for Mac message file")
	}
	for _, f := range findings {
		if strings.HasSuffix(f.Path, "notes.txt") {
			t.Errorf("mail-only scan must not scan regular files: %s", f.Path)
		}
	}
	var sawMail bool
	for _, f := range findings {
		if strings.HasSuffix(f.Path, "cache.ost") {
			sawMail = true
			if f.Folder != "Inbox" || f.Subject != "re: onboarding" || f.Line != 3 {
				t.Errorf("mail finding location wrong: %+v", f)
			}
		}
	}
	if !sawMail {
		t.Error("expected a finding from the .ost under AppData")
	}
	var partial bool
	for _, e := range stats.Errors {
		partial = partial || strings.Contains(e, "partially read")
	}
	if !partial {
		t.Errorf("partial store error missing from stats.Errors: %v", stats.Errors)
	}
}

var errFakeCorrupt = fmt.Errorf("truncated b-tree")

// TestMailStoresReportedInNormalScan: without MailOnly, mail stores are
// never opened but must be visible as a coverage gap, not silently binned.
func TestMailStoresReportedInNormalScan(t *testing.T) {
	noOutlookLocations(t)
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "archive.pst"), "binary-ish")
	writeFile(t, filepath.Join(root, "notes.txt"), "ssn 123-45-6789")

	// Two Mac message files in one profile list as that profile, once.
	profile := filepath.Join(root, "Outlook 15 Profiles", "Main Profile")
	writeFile(t, filepath.Join(profile, "Data", "Message Sources", "0", "a.olk15MsgSource"), "Subject: x\r\n\r\nhi")
	writeFile(t, filepath.Join(profile, "Data", "Message Sources", "1", "b.olk15MsgSource"), "Subject: y\r\n\r\nhi")

	findings, stats, err := Scan([]string{root}, Options{MaxSizeBytes: 1 << 20, Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	if stats.FilesMail != 3 || len(stats.MailSkipped) != 2 {
		t.Errorf("mail stores not reported as skipped (want 3 counted, 2 listed): %+v", stats)
	}
	listed := strings.Join(stats.MailSkipped, "\n")
	if !strings.Contains(listed, "archive.pst") || !strings.Contains(listed, profile) || strings.Contains(listed, ".olk15MsgSource") {
		t.Errorf("skipped list should name the .pst and the profile folder, not each message: %v", stats.MailSkipped)
	}
	if len(findings) == 0 {
		t.Error("regular files should still be scanned")
	}
}

// TestCredentialCSVSecrets: findings in a password-export CSV carry the
// row's password in Redact so masked output can hide it; other CSVs don't.
func TestCredentialCSVSecrets(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Chrome Passwords.csv"),
		"name,url,username,password\n"+
			"macys,https://www.macys.com/account/signin,ann@nvtsa.com,Jmmyann822\n"+
			"fitbit,https://accounts.fitbit.com/login,ann@nvtsa.com,family7\n")
	writeFile(t, filepath.Join(root, "contacts.csv"),
		"name,email\nAnn,ann@nvtsa.com\n")

	findings, _, err := Scan([]string{root}, Options{MaxSizeBytes: 1 << 20, Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	var pwRows, plain int
	for _, f := range findings {
		switch f.FileName {
		case "Chrome Passwords.csv":
			pwRows++
			var want string
			switch f.Line {
			case 2:
				want = "Jmmyann822"
			case 3:
				want = "family7"
			default:
				t.Errorf("unexpected finding line %d", f.Line)
				continue
			}
			if len(f.Redact) != 1 || f.Redact[0] != want {
				t.Errorf("line %d Redact = %q, want [%q]", f.Line, f.Redact, want)
			}
		case "contacts.csv":
			plain++
			if f.Redact != nil {
				t.Errorf("contacts.csv finding should have no Redact, got %q", f.Redact)
			}
		}
	}
	if pwRows == 0 || plain == 0 {
		t.Fatalf("expected findings in both files, got pwRows=%d plain=%d", pwRows, plain)
	}
}

func TestCSVSecrets(t *testing.T) {
	// Quoted secret containing a comma; short secret skipped.
	got := csvSecrets("x.csv", "url,username,password\na.com,u1,\"p,w1234\"\nb.com,u2,ab\n")
	if len(got[2]) != 1 || got[2][0] != "p,w1234" {
		t.Errorf("line 2 = %q, want [\"p,w1234\"]", got[2])
	}
	if got[3] != nil {
		t.Errorf("short secret should be skipped, got %q", got[3])
	}
	if csvSecrets("x.txt", "url,username,password\na.com,u,secret99\n") != nil {
		t.Error("non-.csv file should return nil")
	}
	if csvSecrets("x.csv", "name,email\nann,a@b.com\n") != nil {
		t.Error("CSV without a secret column should return nil")
	}
}

// TestScanCategoryFilter: Options.Categories restricts findings to the
// selected PII types; empty means all.
func TestScanCategoryFilter(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "notes.txt"), "ssn 123-45-6789 and email ann@nvtsa.com\n")

	all, _, err := Scan([]string{root}, Options{MaxSizeBytes: 1 << 20, Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	cats := map[string]bool{}
	for _, f := range all {
		cats[f.Category] = true
	}
	if !cats["SSN"] || !cats["Email Address"] {
		t.Fatalf("unfiltered scan should find both types, got %v", cats)
	}

	only, _, err := Scan([]string{root}, Options{MaxSizeBytes: 1 << 20, Workers: 1, Categories: []string{"SSN"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(only) == 0 {
		t.Fatal("expected SSN finding")
	}
	for _, f := range only {
		if f.Category != "SSN" {
			t.Errorf("unselected category %q leaked through", f.Category)
		}
	}
}

// TestExcludeEmails: exact addresses and whole domains are suppressed from
// Email Address findings; every accepted spelling normalizes the same way.
func TestExcludeEmails(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "letter.txt"),
		"Header: info@cybxsecurity.com\n"+
			"Also: SALES@CybXSecurity.com\n"+
			"Customer: ann.smith@comcast.net\n"+
			"Sub: help@mail.cybxsecurity.com\n")

	scan := func(excl ...string) map[string]bool {
		findings, _, err := Scan([]string{root}, Options{
			MaxSizeBytes: 1 << 20, Workers: 1, ExcludeEmails: excl,
		})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, f := range findings {
			if f.Category == "Email Address" {
				got[f.Match] = true
			}
		}
		return got
	}

	// No exclusions: all four addresses reported.
	if got := scan(); len(got) != 4 {
		t.Fatalf("baseline = %v, want 4 addresses", got)
	}

	// Exact address, case-insensitive.
	got := scan("INFO@cybxsecurity.com")
	if got["info@cybxsecurity.com"] || !got["SALES@CybXSecurity.com"] {
		t.Errorf("exact exclusion wrong: %v", got)
	}

	// Whole domain, in each accepted spelling; subdomain is NOT covered.
	for _, pattern := range []string{"@cybxsecurity.com", "cybxsecurity.com", "*@cybxsecurity.com"} {
		got := scan(pattern)
		if got["info@cybxsecurity.com"] || got["SALES@CybXSecurity.com"] {
			t.Errorf("%q: domain addresses leaked: %v", pattern, got)
		}
		if !got["ann.smith@comcast.net"] || !got["help@mail.cybxsecurity.com"] {
			t.Errorf("%q: over-excluded: %v", pattern, got)
		}
	}

	// Comma-separated entry covers both forms at once.
	got = scan("ann.smith@comcast.net, @cybxsecurity.com")
	if len(got) != 1 || !got["help@mail.cybxsecurity.com"] {
		t.Errorf("comma-separated exclusions wrong: %v", got)
	}
}

// A blank exclude pattern is a substring of every path; it must be ignored,
// not turn the scan into a clean report of zero files.
func TestBlankExcludeIgnored(t *testing.T) {
	t.Setenv("PRIVACYLENS_DATA_DIR", t.TempDir())
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.txt"), "SSN: 219-09-9999\n")
	writeFile(t, filepath.Join(root, "skip.bak"), "SSN: 219-09-9999\n")
	findings, stats, err := Scan([]string{root}, Options{
		Workers: 1, MaxSizeBytes: 1 << 20, Excludes: []string{"", "  ", "*.bak"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.FilesScanned != 1 || len(findings) != 1 {
		t.Errorf("scanned %d files with %d findings, want 1 and 1", stats.FilesScanned, len(findings))
	}
}

// UTF-16 text files are scanned like any other text file.
func TestScanUTF16File(t *testing.T) {
	t.Setenv("PRIVACYLENS_DATA_DIR", t.TempDir())
	root := t.TempDir()
	raw := []byte{0xFF, 0xFE}
	for _, c := range []byte("header\r\nEmployee SSN: 219-09-9999\r\n") {
		raw = append(raw, c, 0)
	}
	if err := os.WriteFile(filepath.Join(root, "export.txt"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	findings, _, err := Scan([]string{root}, Options{Workers: 1, MaxSizeBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Category != "SSN" || findings[0].Line != 2 {
		t.Fatalf("findings = %+v, want one SSN on line 2", findings)
	}
}

// Trimming the context to its radius must not split a multi-byte character.
func TestContextSnippetKeepsRunesWhole(t *testing.T) {
	for pad := 55; pad < 70; pad++ {
		text := strings.Repeat("é", pad) + " 219-09-9999 " + strings.Repeat("日", pad)
		start := strings.Index(text, "219")
		got := contextSnippet(text, detect.Match{Start: start, End: start + 11})
		if !utf8.ValidString(got) {
			t.Fatalf("pad %d: snippet is not valid UTF-8: %q", pad, got)
		}
		if !strings.Contains(got, "219-09-9999") {
			t.Fatalf("pad %d: snippet lost the match: %q", pad, got)
		}
	}
}

// Documents in formats the scanner cannot open are listed as a coverage gap,
// not folded into the anonymous skipped count.
func TestUnreadableDocsReported(t *testing.T) {
	t.Setenv("PRIVACYLENS_DATA_DIR", t.TempDir())
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "old-payroll.XLS"), "\xd0\xcf\x11\xe0binary")
	writeFile(t, filepath.Join(root, "letter.doc"), "\xd0\xcf\x11\xe0binary")
	writeFile(t, filepath.Join(root, "photo.gif"), "GIF89a")
	_, stats, err := Scan([]string{root}, Options{Workers: 1, MaxSizeBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if stats.FilesDocs != 2 || len(stats.UnreadDocs) != 2 || stats.FilesSkipped != 1 {
		t.Errorf("unreadable docs = %d (%v), skipped = %d; want 2 and 1", stats.FilesDocs, stats.UnreadDocs, stats.FilesSkipped)
	}
}

// Exclude patterns ignore case: "*.png" must skip Screenshot.PNG too, and a
// folder name typed in the wrong case must still prune the folder.
func TestExcludesIgnoreCase(t *testing.T) {
	t.Setenv("PRIVACYLENS_DATA_DIR", t.TempDir())
	root := t.TempDir()
	const pii = "SSN: 219-09-9999\n"
	writeFile(t, filepath.Join(root, "keep.txt"), pii)
	for _, name := range []string{"a.png", "B.PNG", "sub/C.Png", "Backups/old.txt", "backups2/x.txt"} {
		writeFile(t, filepath.Join(root, filepath.FromSlash(name)), pii)
	}
	findings, stats, err := Scan([]string{root}, Options{
		Workers: 1, MaxSizeBytes: 1 << 20, Excludes: []string{"*.PNG", "backups"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || filepath.Base(findings[0].Path) != "keep.txt" {
		t.Errorf("findings = %+v, want only keep.txt", findings)
	}
	// Three image files skipped by name. Both folders are pruned (Backups
	// by name, backups2 as a path substring), so their files are never
	// reached and never counted.
	if stats.FilesSkipped != 3 {
		t.Errorf("FilesSkipped = %d, want 3", stats.FilesSkipped)
	}
}

func TestErrorsAreOneLine(t *testing.T) {
	if got := oneLine("ocr failed: Error in findFileFormatStream\n  second line\r\n\tthird"); got != "ocr failed: Error in findFileFormatStream second line third" {
		t.Errorf("oneLine = %q", got)
	}
}

// TestMailScanAddsOutlookLocations: a mail scan searches where Outlook
// keeps its data even when the chosen paths do not reach it, says so in
// stats, and skips locations already inside a root.
func TestMailScanAddsOutlookLocations(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "notes.txt"), "ssn 123-45-6789")
	outlook := filepath.Join(t.TempDir(), "Outlook 15 Profiles")
	msg := filepath.Join(outlook, "Main Profile", "Data", "Message Sources", "0", "m.olk15MsgSource")
	writeFile(t, msg, "Subject: hi\r\nContent-Type: text/plain\r\n\r\nssn 219-09-9999\r\n")
	inside := filepath.Join(root, "Outlook Files")
	writeFile(t, filepath.Join(inside, "readme.txt"), "x")
	missing := filepath.Join(t.TempDir(), "nope")

	saved := outlookDataLocations
	outlookDataLocations = func() []string { return []string{outlook, inside, missing} }
	t.Cleanup(func() { outlookDataLocations = saved })

	findings, stats, err := Scan([]string{root}, Options{MaxSizeBytes: 1 << 20, Workers: 2, MailOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(stats.MailRoots) != 1 || stats.MailRoots[0] != outlook {
		t.Errorf("MailRoots = %v, want just %s (inside-root and missing locations skipped)", stats.MailRoots, outlook)
	}
	if len(findings) != 1 || findings[0].Path != msg {
		t.Errorf("findings = %+v, want the SSN from the Outlook location", findings)
	}
	if len(stats.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", stats.Warnings)
	}

	// Without MailOnly nothing is added.
	_, stats, err = Scan([]string{root}, Options{MaxSizeBytes: 1 << 20, Workers: 2})
	if err != nil || len(stats.MailRoots) != 0 {
		t.Errorf("normal scan must not add Outlook locations: %v %v", stats.MailRoots, err)
	}
}

// TestMailScanWarnsWhenOutlookUnreadable: an Outlook location the process
// may not read (macOS without Full Disk Access) becomes a loud warning,
// never a quiet clean result.
func TestMailScanWarnsWhenOutlookUnreadable(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions and a non-root user")
	}
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "notes.txt"), "x")
	outlook := filepath.Join(t.TempDir(), "Outlook 15 Profiles")
	if err := os.MkdirAll(outlook, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outlook, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(outlook, 0o700) })
	saved := outlookDataLocations
	outlookDataLocations = func() []string { return []string{outlook} }
	t.Cleanup(func() { outlookDataLocations = saved })

	_, stats, err := Scan([]string{root}, Options{MaxSizeBytes: 1 << 20, Workers: 2, MailOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(stats.Warnings) != 1 || !strings.Contains(stats.Warnings[0], "NOT searched") || !strings.Contains(stats.Warnings[0], outlook) {
		t.Fatalf("Warnings = %v, want one naming the unreadable Outlook location", stats.Warnings)
	}
	if runtime.GOOS == "darwin" && !strings.Contains(stats.Warnings[0], "Full Disk Access") {
		t.Errorf("macOS warning should explain Full Disk Access: %s", stats.Warnings[0])
	}
}

// noOutlookLocations keeps a mail-scan test from also walking whatever
// Outlook data the machine running the tests happens to have.
func noOutlookLocations(t *testing.T) {
	t.Helper()
	saved := outlookDataLocations
	outlookDataLocations = func() []string { return nil }
	t.Cleanup(func() { outlookDataLocations = saved })
}
