// Package scanner walks directories, extracts text from each file, and runs
// the PII detectors, producing findings with file locations and context.
package scanner

import (
	"context"
	"encoding/csv"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/rdataback/privacylens/internal/detect"
	"github.com/rdataback/privacylens/internal/extract"
	"github.com/rdataback/privacylens/internal/paths"
)

// Options controls a scan.
type Options struct {
	Excludes     []string // glob (matched on name) or substring (matched on path)
	MaxSizeBytes int64    // files larger than this are skipped
	Workers      int
	// MemoryBudgetBytes bounds the aggregate size of files being extracted by
	// workers at once. Zero uses a conservative 256 MiB default.
	MemoryBudgetBytes int64
	MinConfidence     detect.Confidence

	// ScanAll disables the built-in directory skip list (AppData, caches,
	// Recycle Bin, node_modules — see builtinSkipDirs), scanning everything
	// the walk reaches.
	ScanAll bool

	// IncludeCloud scans cloud-placeholder files (OneDrive Files On-Demand,
	// evicted iCloud files) whose content is not local. Off by default:
	// reading a placeholder makes the sync engine download it, so scanning
	// a large online-only folder would pull the whole thing over the
	// network and fill the disk.
	IncludeCloud bool

	// MailOnly runs a targeted mail scan: only Outlook mail stores
	// (.pst/.ost) are scanned, message by message, and everything else is
	// passed over. The AppData prune is lifted for the walk — that is where
	// Outlook keeps the live .ost cache. Without MailOnly, mail stores are
	// never opened; they are counted in Stats.MailSkipped instead.
	MailOnly bool

	// Categories restricts detection to these category display names (as
	// returned by detect.Categories()); empty means every detector runs.
	Categories []string

	// ExcludeEmails suppresses Email Address findings for known-benign
	// addresses — a company address printed in every letter footer is
	// letterhead, not PII. Each entry is an exact address
	// ("info@cybxsecurity.com") or a domain ("@cybxsecurity.com"; the bare
	// "cybxsecurity.com" and "*@cybxsecurity.com" spellings are accepted
	// too), matched case-insensitively. Domains match exactly — a
	// subdomain needs its own entry.
	ExcludeEmails []string

	// categorySet is Categories as a lookup, built once by Scan.
	categorySet map[string]bool

	// emailExcludes is ExcludeEmails normalized by Scan.
	emailExcludes []string

	// mailRead reads a mail store; tests stub it. Nil means the real
	// extract.ReadMailStore.
	mailRead func(string) ([]extract.MailItem, error)

	// OnFindings, if set, receives each file's findings as soon as that file
	// has been scanned, letting callers stream results (e.g. to a log a SIEM
	// agent tails) instead of waiting for the whole scan. Calls are
	// serialized on the collector goroutine; findings arrive in file
	// completion order, not the sorted order of the final result.
	OnFindings func([]Finding)

	// Progress, if set, receives progress updates for interactive display:
	// files done so far, total files discovered, and findings so far.
	// During the discovery walk it is called with done == 0 and a growing
	// total (every few hundred files), so a long walk over a large tree is
	// visibly alive before scanning starts; after that it is called on the
	// collector goroutine after each file completes (whatever the outcome).
	Progress func(done, total, findings int)
}

// Finding is one PII hit, located within a file.
type Finding struct {
	Path       string `json:"path"`
	FileName   string `json:"file_name"`
	Category   string `json:"category"`
	Confidence string `json:"confidence"`
	Line       int    `json:"line"`
	Match      string `json:"match"`
	Context    string `json:"context"`
	// OCR marks findings read via OCR rather than an embedded text layer.
	// OCR misreads characters (0/O, 1/l), so consumers may want to weight
	// these lower or verify against the source document.
	OCR bool `json:"ocr,omitempty"`
	// Page is the 1-based page number for findings in OCR'd multi-page
	// documents (Line is then the line within that page). Zero for
	// documents without page structure.
	Page int `json:"page,omitempty"`
	// Folder and Subject locate a finding inside a mail store (MailOnly
	// scans): the Outlook folder and the message's subject. Line is then
	// the message's 1-based position within that folder, not a text line.
	Folder  string `json:"folder,omitempty"`
	Subject string `json:"subject,omitempty"`
	// Redact holds secret values that share this finding's line but are not
	// themselves the match — e.g. the password column of a credential-export
	// CSV sitting right next to a matched email. Masked output hides them
	// completely; the field itself never serializes.
	Redact []string `json:"-"`
}

// Stats summarizes what the scan covered.
type Stats struct {
	FilesScanned int      `json:"files_scanned"`
	FilesOCR     int      `json:"files_ocr"` // subset of FilesScanned read via OCR
	FilesSkipped int      `json:"files_skipped"`
	FilesNeedOCR int      `json:"files_need_ocr"`
	FilesCloud   int      `json:"files_cloud_skipped"`
	FilesMail    int      `json:"files_mail_skipped"`    // mail stores seen but NOT searched (run a MailOnly scan)
	FilesDocs    int      `json:"files_unreadable_docs"` // documents in formats that cannot be opened (.doc, .xls, .msg, …)
	FilesErrored int      `json:"files_errored"`
	NeedOCR      []string `json:"need_ocr_files,omitempty"`       // image-only documents that were NOT searched
	CloudSkipped []string `json:"cloud_skipped_files,omitempty"`  // cloud placeholders that were NOT searched
	MailSkipped  []string `json:"mail_store_files,omitempty"`     // mail stores that were NOT searched
	UnreadDocs   []string `json:"unreadable_doc_files,omitempty"` // unsupported-format documents that were NOT searched
	Errors       []string `json:"errors,omitempty"`
}

type fileResult struct {
	findings  []Finding
	skipped   bool
	needsOCR  bool
	cloud     bool
	mailStore bool  // a .pst/.ost seen outside a MailOnly scan
	unreadDoc bool  // a document in a format the scanner cannot open
	warn      error // partial-read problem on a file that still produced results
	ocr       bool  // scanned via OCR
	err       error
	path      string
}

// Scan walks each root (a directory or single file), scans every supported
// file, and returns all findings sorted by path and line. A root that cannot
// be stat'ed is a hard error; unreadable files inside a walk are recorded in
// Stats.Errors and the scan continues.
func Scan(roots []string, opts Options) ([]Finding, Stats, error) {
	return ScanContext(context.Background(), roots, opts)
}

// ScanContext is Scan with cooperative cancellation. Cancellation stops the
// directory walk, prevents new extraction work, and lets in-flight files drain.
func ScanContext(ctx context.Context, roots []string, opts Options) ([]Finding, Stats, error) {
	if opts.Workers < 1 {
		opts.Workers = 1
	}
	if opts.Workers > 16 {
		opts.Workers = 16
	}
	if opts.MemoryBudgetBytes <= 0 {
		opts.MemoryBudgetBytes = 256 << 20
	}
	limiter := newByteLimiter(opts.MemoryBudgetBytes)
	if len(opts.Categories) > 0 {
		opts.categorySet = map[string]bool{}
		for _, c := range opts.Categories {
			opts.categorySet[c] = true
		}
	}
	opts.emailExcludes = normalizeEmailExcludes(opts.ExcludeEmails)
	opts.Excludes = cleanExcludes(opts.Excludes)
	var stats Stats
	var files []string

	selfDir := selfDataDir()
	selfExe := selfExecutable()

	for _, root := range roots {
		if err := ctx.Err(); err != nil {
			return nil, stats, err
		}
		info, err := os.Stat(root)
		if err != nil {
			if runtime.GOOS == "windows" && strings.HasPrefix(root, "/") {
				return nil, stats, fmt.Errorf(`cannot access %s (Windows paths need a drive letter, e.g. C:\Users): %w`, root, err)
			}
			return nil, stats, fmt.Errorf("cannot access %s: %w", root, err)
		}
		if !info.IsDir() {
			files = append(files, root)
			continue
		}
		// A root that is itself a symlink or junction (e.g. Parallels'
		// C:\Mac\Home) must be resolved first: WalkDir lstats the root and
		// never follows a link, so an unresolved link root walks nothing —
		// silently. Only link roots are resolved; regular paths keep the
		// spelling the user configured.
		if lst, lerr := os.Lstat(root); lerr == nil && lst.Mode()&fs.ModeSymlink != 0 {
			if resolved, rerr := filepath.EvalSymlinks(root); rerr == nil {
				root = resolved
			}
		}
		walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err != nil {
				stats.FilesErrored++
				stats.Errors = append(stats.Errors, fmt.Sprintf("%s: %v", p, err))
				return nil
			}
			if d.IsDir() {
				if d.Name() == ".git" || excluded(p, d.Name(), opts.Excludes) {
					return fs.SkipDir
				}
				// Built-in skip list: app caches and OS state that yield
				// noise findings and enormous walk times. A root pointed
				// explicitly at (or inside) one still scans. Mail scans walk
				// everything — Outlook keeps the live .ost under AppData,
				// and the filter below drops non-mail files anyway.
				if !opts.ScanAll && !opts.MailOnly && p != root && builtinSkipDir(d.Name()) {
					return fs.SkipDir
				}
				// Never descend into PrivacyLens's own data directory:
				// saved reports and the findings log restate PII found
				// elsewhere, so scanning them double-reports every hit.
				// A root explicitly pointed at it still scans (p != root).
				if selfDir != "" && p != root && isSelfDir(p, selfDir) {
					return fs.SkipDir
				}
				return nil
			}
			if !walkableType(d.Type()) {
				return nil
			}
			// Targeted mail scan: everything but mail stores is passed
			// over without being counted — the walk is a search for
			// .pst/.ost, not a scan that skipped a million files.
			if opts.MailOnly && !extract.IsMailStore(p) {
				return nil
			}
			if excluded(p, d.Name(), opts.Excludes) {
				stats.FilesSkipped++
				return nil
			}
			files = append(files, p)
			if opts.Progress != nil && len(files)%512 == 0 {
				opts.Progress(0, len(files), 0)
			}
			return nil
		})
		if walkErr != nil {
			return nil, stats, walkErr
		}
	}

	jobs := make(chan string)
	results := make(chan fileResult)
	var wg sync.WaitGroup
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				r := scanFileContext(ctx, path, opts, selfExe, limiter)
				results <- r
			}
		}()
	}
	go func() {
		for _, f := range files {
			select {
			case jobs <- f:
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				close(results)
				return
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	var findings []Finding
	done := 0
	for r := range results {
		switch {
		case r.err != nil:
			stats.FilesErrored++
			stats.Errors = append(stats.Errors, fmt.Sprintf("%s: %v", r.path, r.err))
		case r.needsOCR:
			stats.FilesNeedOCR++
			stats.NeedOCR = append(stats.NeedOCR, r.path)
		case r.cloud:
			stats.FilesCloud++
			stats.CloudSkipped = append(stats.CloudSkipped, r.path)
		case r.mailStore:
			stats.FilesMail++
			stats.MailSkipped = append(stats.MailSkipped, r.path)
		case r.unreadDoc:
			stats.FilesDocs++
			stats.UnreadDocs = append(stats.UnreadDocs, r.path)
		case r.skipped:
			stats.FilesSkipped++
		default:
			if r.warn != nil {
				stats.Errors = append(stats.Errors, fmt.Sprintf("%s: partially read: %v", r.path, r.warn))
			}
			stats.FilesScanned++
			if r.ocr {
				stats.FilesOCR++
			}
			findings = append(findings, r.findings...)
			if opts.OnFindings != nil && len(r.findings) > 0 {
				opts.OnFindings(r.findings)
			}
		}
		done++
		if opts.Progress != nil {
			opts.Progress(done, len(files), len(findings))
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, stats, err
	}
	sort.Strings(stats.NeedOCR)
	sort.Strings(stats.CloudSkipped)
	sort.Strings(stats.MailSkipped)
	sort.Strings(stats.UnreadDocs)

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Category < findings[j].Category
	})
	return findings, stats, nil
}

// builtinSkipDirs are directory names never descended into by default:
// per-user application state and caches (AppData holds browser caches and
// app databases — the bulk of a profile's file count, and its documents,
// like Outlook OST/PST stores, are formats this scanner cannot parse
// anyway), OS recycle/system folders, and dependency trees. Options.ScanAll
// disables the list; an explicit root at or inside one always scans.
var builtinSkipDirs = []string{
	"AppData",                   // Windows per-user app state and caches
	"$Recycle.Bin",              // Windows recycle bin
	"System Volume Information", // Windows restore/index state
	"node_modules",
	".Trash", // macOS trash
	".cache", // Linux XDG cache
}

// builtinSkipDir matches case-insensitively: Windows and macOS filesystems
// are, and a cache dir is a cache dir regardless of its casing.
func builtinSkipDir(name string) bool {
	for _, s := range builtinSkipDirs {
		if strings.EqualFold(name, s) {
			return true
		}
	}
	return false
}

// selfDataDir returns the PrivacyLens data directory (symlinks resolved) for
// self-exclusion during walks, or "" if it cannot be determined.
func selfDataDir() string {
	d, err := paths.Locate()
	if err != nil {
		return ""
	}
	if r, err := filepath.EvalSymlinks(d); err == nil {
		d = r
	}
	return d
}

// selfExecutable returns the FileInfo of the running binary, or nil if it
// cannot be determined. Compared with os.SameFile so renames, hard links,
// and case differences don't defeat the check.
func selfExecutable() os.FileInfo {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	fi, err := os.Stat(exe)
	if err != nil {
		return nil
	}
	return fi
}

// isSelfDir reports whether walked directory p is the PrivacyLens data
// directory selfDir. p may be relative to the walk root, so compare absolute
// paths, case-insensitively on the OSes whose default filesystems are.
func isSelfDir(p, selfDir string) bool {
	abs, err := filepath.Abs(p)
	if err != nil {
		return false
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		abs = r
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.EqualFold(abs, selfDir)
	}
	return abs == selfDir
}

// walkableType reports whether a non-directory entry should be queued for
// scanning. Regular files qualify, and so do ModeIrregular ones: since
// Go 1.23 Windows reports any file carrying a reparse tag the runtime does
// not recognize as irregular — which includes every OneDrive Files
// On-Demand placeholder, hydrated or not, so requiring IsRegular silently
// dropped most of a synced OneDrive tree. Irregular entries still pass
// through scanFile's cloud-placeholder check, which decides whether reading
// them is safe. Symlinks, devices, pipes, and sockets are never scanned.
func walkableType(t fs.FileMode) bool {
	return t&(fs.ModeSymlink|fs.ModeDevice|fs.ModeNamedPipe|fs.ModeSocket) == 0
}

// cleanExcludes drops blank patterns. An empty pattern is a substring of
// every path, so a stray "" in a manifest (or -exclude "$UNSET_VAR") would
// exclude every file and report a clean scan of nothing.
func cleanExcludes(patterns []string) []string {
	var out []string
	for _, p := range patterns {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return out
}

func excluded(path, name string, patterns []string) bool {
	for _, pat := range patterns {
		if ok, _ := filepath.Match(pat, name); ok {
			return true
		}
		if strings.Contains(path, pat) {
			return true
		}
	}
	return false
}

func scanFile(path string, opts Options, selfExe os.FileInfo) fileResult {
	return scanFileContext(context.Background(), path, opts, selfExe, nil)
}

func scanFileContext(ctx context.Context, path string, opts Options, selfExe os.FileInfo, limiter *byteLimiter) fileResult {
	fi, err := os.Stat(path)
	if err != nil {
		return fileResult{path: path, err: err}
	}
	// Never scan the running executable itself.
	if selfExe != nil && os.SameFile(selfExe, fi) {
		return fileResult{path: path, skipped: true}
	}
	if fi.Size() > opts.MaxSizeBytes {
		return fileResult{path: path, skipped: true}
	}
	if limiter != nil {
		release, err := limiter.acquire(ctx, fi.Size())
		if err != nil {
			return fileResult{path: path, err: err}
		}
		defer release()
	}
	// Cloud placeholders (OneDrive on-demand, evicted iCloud files) have no
	// local content: reading one triggers a download. Skip and report them
	// as a coverage gap unless the caller opted in.
	if !opts.IncludeCloud && isCloudPlaceholder(fi) {
		return fileResult{path: path, cloud: true}
	}
	if extract.IsMailStore(path) {
		if !opts.MailOnly {
			return fileResult{path: path, mailStore: true}
		}
		return scanMailStore(path, opts)
	}
	text, status, err := extract.FromFile(path)
	if err != nil {
		return fileResult{path: path, err: err}
	}
	switch status {
	case extract.StatusUnsupported:
		return fileResult{path: path, skipped: true}
	case extract.StatusNeedsOCR:
		return fileResult{path: path, needsOCR: true}
	case extract.StatusUnreadableDoc:
		return fileResult{path: path, unreadDoc: true}
	}
	viaOCR := status == extract.StatusOCR

	matches := detect.ScanOnly(text, opts.categorySet)
	var findings []Finding
	secrets := csvSecrets(path, text)
	pos := newLocator(viaOCR && strings.ContainsRune(text, '\f'))
	for _, m := range matches {
		line, page := pos.advance(text, m.Start)
		if m.Confidence < opts.MinConfidence {
			continue
		}
		if opts.excludedEmail(m.Category, m.Value) {
			continue
		}
		findings = append(findings, Finding{
			Path:       path,
			FileName:   filepath.Base(path),
			Category:   m.Category,
			Confidence: m.Confidence.String(),
			Line:       line,
			Page:       page,
			Match:      m.Value,
			Context:    contextSnippet(text, m),
			OCR:        viaOCR,
			Redact:     secrets[line],
		})
	}
	return fileResult{path: path, findings: findings, ocr: viaOCR}
}

// byteLimiter is a coarse weighted semaphore. One token represents 1 MiB;
// requests larger than the budget consume the full budget and run alone.
type byteLimiter struct {
	mu     sync.Mutex // makes each weighted acquisition atomic
	tokens chan struct{}
}

func newByteLimiter(bytes int64) *byteLimiter {
	n := int((bytes + (1 << 20) - 1) >> 20)
	if n < 1 {
		n = 1
	}
	return &byteLimiter{tokens: make(chan struct{}, n)}
}

func (l *byteLimiter) acquire(ctx context.Context, bytes int64) (func(), error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := int((bytes + (1 << 20) - 1) >> 20)
	if n < 1 {
		n = 1
	}
	if n > cap(l.tokens) {
		n = cap(l.tokens)
	}
	got := 0
	for got < n {
		select {
		case l.tokens <- struct{}{}:
			got++
		case <-ctx.Done():
			for got > 0 {
				<-l.tokens
				got--
			}
			return nil, ctx.Err()
		}
	}
	return func() {
		for i := 0; i < n; i++ {
			<-l.tokens
		}
	}, nil
}

// normalizeEmailExcludes flattens comma-separated entries, lowercases, and
// canonicalizes each pattern: an address ("info@x.com") stays exact, while
// "@x.com", "x.com", and "*@x.com" all become the domain form "@x.com".
func normalizeEmailExcludes(patterns []string) []string {
	var out []string
	for _, p := range patterns {
		for _, e := range strings.Split(p, ",") {
			e = strings.ToLower(strings.TrimSpace(e))
			e = strings.TrimPrefix(e, "*")
			if e == "" || e == "@" {
				continue
			}
			if !strings.Contains(e, "@") {
				e = "@" + e
			}
			out = append(out, e)
		}
	}
	return out
}

// excludedEmail reports whether an Email Address match is on the exclusion
// list. A pattern starting with "@" matches any local part at exactly that
// domain; anything else must equal the whole address. Case-insensitive.
func (o *Options) excludedEmail(category, value string) bool {
	if len(o.emailExcludes) == 0 || category != "Email Address" {
		return false
	}
	v := strings.ToLower(value)
	for _, p := range o.emailExcludes {
		if strings.HasPrefix(p, "@") {
			if strings.HasSuffix(v, p) {
				return true
			}
		} else if v == p {
			return true
		}
	}
	return false
}

// csvSecrets detects credential-export CSVs — Chrome, Edge, Firefox, Safari,
// LastPass, and Bitwarden password exports all carry a password column — and
// returns each row's secret values keyed by the 1-based line they appear on.
// A finding on such a line carries them in Redact so masked output can hide
// the password sitting next to a matched username. Non-CSV files and CSVs
// without a secret column return nil.
func csvSecrets(path, text string) map[int][]string {
	if !strings.EqualFold(filepath.Ext(path), ".csv") {
		return nil
	}
	r := csv.NewReader(strings.NewReader(text))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	header, err := r.Read()
	if err != nil {
		return nil
	}
	var cols []int
	for i, name := range header {
		n := strings.ToLower(strings.TrimSpace(name))
		if n == "password" || strings.HasSuffix(n, "_password") || n == "otpauth" || n == "totp" {
			cols = append(cols, i)
		}
	}
	if len(cols) == 0 {
		return nil
	}
	secrets := map[int][]string{}
	for {
		rec, err := r.Read()
		if err != nil {
			return secrets // EOF or a malformed row; keep what parsed
		}
		for _, c := range cols {
			// Values under 4 bytes are skipped: masking replaces every
			// occurrence of the secret in the context, and a tiny value
			// would wildcard common substrings of the surrounding text.
			if c >= len(rec) || len(rec[c]) < 4 {
				continue
			}
			recLine, _ := r.FieldPos(0)
			secrets[recLine] = append(secrets[recLine], rec[c])
			// A quoted secret can start on a later physical line than its
			// record; map that line too so any finding there hides it.
			if fieldLine, _ := r.FieldPos(c); fieldLine != recLine {
				secrets[fieldLine] = append(secrets[fieldLine], rec[c])
			}
		}
	}
}

// scanMailStore runs the detectors over every item of a .pst/.ost,
// message by message. Findings carry the Outlook folder and subject, with
// Line holding the item's position in its folder. A partially corrupt
// store keeps its readable findings; the problem lands in Stats.Errors.
func scanMailStore(path string, opts Options) fileResult {
	readMail := opts.mailRead
	if readMail == nil {
		readMail = extract.ReadMailStore
	}
	items, rerr := readMail(path)
	if len(items) == 0 && rerr != nil {
		return fileResult{path: path, err: rerr}
	}
	var findings []Finding
	for _, item := range items {
		for _, m := range detect.ScanOnly(item.Text, opts.categorySet) {
			if m.Confidence < opts.MinConfidence {
				continue
			}
			if opts.excludedEmail(m.Category, m.Value) {
				continue
			}
			findings = append(findings, Finding{
				Path:       path,
				FileName:   filepath.Base(path),
				Category:   m.Category,
				Confidence: m.Confidence.String(),
				Line:       item.Index,
				Folder:     item.Folder,
				Subject:    item.Subject,
				Match:      m.Value,
				Context:    contextSnippet(item.Text, m),
			})
		}
	}
	return fileResult{path: path, findings: findings, warn: rerr}
}

// locator converts byte offsets of successive (ascending) matches into line
// numbers — and, for paged text (OCR'd PDFs, pages joined with form feeds),
// page numbers with the line counted within the page.
type locator struct {
	paged   bool
	line    int
	page    int
	lastPos int
}

func newLocator(paged bool) *locator {
	page := 0
	if paged {
		page = 1
	}
	return &locator{paged: paged, line: 1, page: page}
}

// advance moves to offset (which must not decrease across calls) and
// returns the line and page there; page is 0 for unpaged text.
func (l *locator) advance(text string, offset int) (line, page int) {
	seg := text[l.lastPos:offset]
	l.lastPos = offset
	if l.paged {
		if ff := strings.Count(seg, "\f"); ff > 0 {
			l.page += ff
			seg = seg[strings.LastIndexByte(seg, '\f')+1:]
			l.line = 1
		}
	}
	l.line += strings.Count(seg, "\n")
	return l.line, l.page
}

// contextSnippet returns the line containing the match, trimmed to at most
// ~60 characters on either side of the match, with control characters
// collapsed to spaces. The line-boundary searches are bounded to that
// radius: since anything further gets trimmed to 60 bytes anyway, an
// unbounded newline scan would cost O(file size) per finding on huge
// single-line files.
func contextSnippet(text string, m detect.Match) string {
	const radius = 60
	start, prefix := 0, ""
	if lo := m.Start - radius - 1; lo >= 0 {
		if nl := strings.LastIndexByte(text[lo:m.Start], '\n'); nl >= 0 {
			start = lo + nl + 1
		} else {
			start = m.Start - radius
			prefix = "…"
		}
	} else if nl := strings.LastIndexByte(text[:m.Start], '\n'); nl >= 0 {
		start = nl + 1
	}
	end, suffix := len(text), ""
	if hi := m.End + radius + 1; hi <= len(text) {
		if nl := strings.IndexByte(text[m.End:hi], '\n'); nl >= 0 {
			end = m.End + nl
		} else {
			end = m.End + radius
			suffix = "…"
		}
	} else if nl := strings.IndexByte(text[m.End:], '\n'); nl >= 0 {
		end = m.End + nl
	}
	// The radius cuts are byte offsets; nudge them inward to rune boundaries
	// so a multi-byte character is never split into garbage at the edges.
	for start < m.Start && !utf8.RuneStart(text[start]) {
		start++
	}
	for end > m.End && end < len(text) && !utf8.RuneStart(text[end]) {
		end--
	}
	snippet := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\t' || r < 32 {
			return ' '
		}
		return r
	}, text[start:end])
	return prefix + strings.TrimSpace(snippet) + suffix
}
