// Package gui serves the browser-based interface: the same scan engine as
// the CLI behind a small localhost-only HTTP API and an embedded single-page
// app.
package gui

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/rdataback/privacylens/internal/detect"
	"github.com/rdataback/privacylens/internal/extract"
	"github.com/rdataback/privacylens/internal/paths"
	"github.com/rdataback/privacylens/internal/report"
	"github.com/rdataback/privacylens/internal/scanner"
)

//go:embed static/index.html
var indexHTML []byte

// Options configures the GUI server.
type Options struct {
	Addr        string // listen address; must stay loopback-only
	OpenBrowser bool
	Tool        string
	Version     string
}

type server struct {
	opts  Options
	token string
	// sysLog is the machine-wide Insights findings log; a field so tests can
	// point it away from the real one.
	sysLog string

	mu   sync.Mutex
	last *report.Report // most recent scan, for report downloads

	// progMu guards prog on its own lock: s.mu is held for the entire scan,
	// and the whole point of the progress endpoint is answering while a scan
	// is running.
	progMu sync.Mutex
	prog   progressState
}

// progressState is what /api/progress returns. During the discovery walk
// done is 0 while total grows; during scanning done climbs toward total.
type progressState struct {
	Active   bool `json:"active"`
	Done     int  `json:"done"`
	Total    int  `json:"total"`
	Findings int  `json:"findings"`
}

// Run starts the GUI server and blocks. Every API request must carry the
// per-session token (printed in the URL), so random local webpages cannot
// drive scans against the filesystem.
func Run(opts Options) error {
	tok := make([]byte, 16)
	if _, err := rand.Read(tok); err != nil {
		return err
	}
	s := &server{opts: opts, token: hex.EncodeToString(tok), sysLog: paths.SystemFindingsLog()}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/scan", s.auth(s.handleScan))
	mux.HandleFunc("/api/progress", s.auth(s.handleProgress))
	mux.HandleFunc("/api/download", s.auth(s.handleDownload))

	ln, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return err
	}
	// Checked before the URL (and its token) is printed or opened anywhere.
	if !ln.Addr().(*net.TCPAddr).IP.IsLoopback() {
		ln.Close()
		return fmt.Errorf("refusing non-loopback GUI address %s", ln.Addr())
	}
	url := fmt.Sprintf("http://%s/?token=%s", ln.Addr(), s.token)
	fmt.Printf("%s GUI running at:\n\n  %s\n\nPress Ctrl+C to stop.\n", opts.Tool, url)
	if opts.OpenBrowser {
		openBrowser(url)
	}
	h := securityHeaders(mux)
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
		// A scan response can legitimately take hours, so WriteTimeout stays
		// unset; request cancellation is propagated to the scan instead.
	}
	return srv.Serve(ln)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	// Example paths must match the host OS: a Unix-style suggestion on
	// Windows leads users to type /Users, which fails to stat.
	examples := "/Users/you/Documents&#10;/shared/finance"
	if runtime.GOOS == "windows" {
		examples = `C:\Users\you\Documents&#10;C:\Users\you\OneDrive`
	}
	// Pre-fill the scan box with the whole user-profiles tree so "open the
	// GUI, press Scan" does something sensible without typing a path. Still
	// just a textarea value — edit or replace it to scan elsewhere.
	defaultPath := "."
	if home, err := os.UserHomeDir(); err == nil {
		defaultPath = filepath.Join(home, "Documents")
		if _, err := os.Stat(defaultPath); err != nil {
			defaultPath = home
		}
	}
	// The PII-type checkboxes come from the detector list itself, so a new
	// detector shows up in the GUI without touching the page.
	cats, _ := json.Marshal(detect.Categories())
	page := bytes.Replace(indexHTML, []byte("__EXAMPLE_PATHS__"), []byte(examples), 1)
	// Escaped: a profile folder may contain & or < (C:\Users\R&D), which
	// must land in the textarea as text, not markup.
	page = bytes.Replace(page, []byte("__DEFAULT_PATHS__"), []byte(html.EscapeString(defaultPath)), 1)
	page = bytes.Replace(page, []byte("__CATEGORIES__"), cats, 1)
	page = bytes.Replace(page, []byte("__VERSION__"), []byte(html.EscapeString(s.opts.Version)), 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(page)
}

func (s *server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-PL-Token")
		if got == "" {
			got = r.URL.Query().Get("token")
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			http.Error(w, "missing or invalid token", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

type scanRequest struct {
	Paths    []string `json:"paths"`
	Excludes []string `json:"excludes"`
	// ExcludeEmails suppresses Email Address findings for known-benign
	// addresses: exact ("info@x.com") or a whole domain ("@x.com").
	ExcludeEmails []string `json:"exclude_emails"`
	MinConfidence string   `json:"min_confidence"`
	MaxSizeMB     int64    `json:"max_size_mb"`
	ShowFull      bool     `json:"show_full"`
	// Categories restricts the scan to these PII types (detector display
	// names); empty means all.
	Categories   []string `json:"categories"`
	OCR          bool     `json:"ocr"`
	IncludeCloud bool     `json:"include_cloud"`
	ScanAll      bool     `json:"scan_all"`
	Mail         bool     `json:"mail"`
	// WazuhLog streams findings to the machine-wide log the installer
	// registered with the SIEM agent. Defaults to true when absent (a
	// pointer so "omitted" and "explicitly off" are distinguishable): the
	// machine-wide log is where Insights actually looks.
	WazuhLog *bool `json:"wazuh_log"`
}

func (s *server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req scanRequest
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.Paths) == 0 {
		http.Error(w, "at least one path is required", http.StatusBadRequest)
		return
	}
	if len(req.Paths) > 256 || len(req.Excludes) > 1024 || len(req.ExcludeEmails) > 1024 {
		http.Error(w, "too many paths or exclusions", http.StatusBadRequest)
		return
	}
	conf, ok := detect.ParseConfidence(req.MinConfidence)
	if !ok {
		conf = detect.Low
	}
	if len(req.Categories) > 0 {
		cats, err := detect.NormalizeCategories(req.Categories)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req.Categories = cats
	}
	if req.MaxSizeMB <= 0 {
		req.MaxSizeMB = 50
	}
	// Mail stores are multi-gigabyte; the GUI's default size box (50) would
	// skip every one, so a mail scan raises an untouched default to 50 GB.
	if req.Mail && req.MaxSizeMB == 50 {
		req.MaxSizeMB = 50 * 1024
	}

	// Serialize scans: the engine is concurrent internally, and the GUI is a
	// single-operator tool.
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reset progress only after winning s.mu, so a queued scan can't stomp
	// on the counters of one already running.
	s.progMu.Lock()
	s.prog = progressState{Active: true}
	s.progMu.Unlock()
	defer func() {
		s.progMu.Lock()
		s.prog.Active = false
		s.progMu.Unlock()
	}()

	// Per-scan OCR toggle; safe because scans are serialized on s.mu.
	extract.SetOCR(req.OCR)
	defer extract.SetOCR(false)

	// Stream events to the findings log while the scan runs so a log
	// shipper (e.g. a Wazuh agent) tailing it ingests findings steadily
	// instead of one end-of-scan burst. The default target is the
	// machine-wide log the Wazuh agent actually tails; writing there needs
	// the setup the installer did (or elevation), so on failure the scan
	// falls back to the per-user log and says so loudly — a scan must
	// never fail just because Insights isn't set up, but rerouting must
	// never be silent either, or "scanned clean" and "Insights never saw
	// it" become indistinguishable.
	//
	// Target selection is shared with the CLI (OpenDefaultFindingsStream):
	// the warning fires only when this machine IS set up for Insights and
	// the log can't be written. A machine that never ran the installer
	// uses the per-user log quietly — a red warning on every laptop scan
	// would teach people to ignore the one that matters.
	var stream *report.EventWriter
	var logPath string
	var streamErr error
	logWarning := ""
	if req.WazuhLog == nil || *req.WazuhLog {
		var warn string
		stream, logPath, warn = report.OpenDefaultFindingsStream(s.sysLog, s.opts.Tool, s.opts.Version, !req.ShowFull)
		switch {
		case stream == nil:
			streamErr = errors.New(warn)
		case warn != "":
			logWarning = fmt.Sprintf("%s%s. Findings went to: %s", strings.ToUpper(warn[:1]), warn[1:], logPath)
		}
	} else {
		stream, logPath, streamErr = report.OpenFindingsStream(s.opts.Tool, s.opts.Version, !req.ShowFull)
	}
	scanOpts := scanner.Options{
		Excludes:      req.Excludes,
		ExcludeEmails: req.ExcludeEmails,
		MaxSizeBytes:  req.MaxSizeMB * 1024 * 1024,
		Workers:       runtime.NumCPU(),
		MinConfidence: conf,
		Categories:    req.Categories,
		IncludeCloud:  req.IncludeCloud,
		ScanAll:       req.ScanAll,
		MailOnly:      req.Mail,
	}
	if stream != nil {
		scanOpts.OnFindings = stream.Findings
	}
	scanOpts.Progress = func(done, total, findings int) {
		s.progMu.Lock()
		s.prog.Done, s.prog.Total, s.prog.Findings = done, total, findings
		s.progMu.Unlock()
	}

	start := time.Now()
	findings, stats, err := scanner.ScanContext(r.Context(), req.Paths, scanOpts)
	if err != nil {
		if stream != nil {
			stream.Abort()
		}
		status := http.StatusBadRequest
		if err == context.Canceled || err == context.DeadlineExceeded {
			status = 499 // client closed request
		}
		http.Error(w, err.Error(), status)
		return
	}
	s.last = &report.Report{
		Tool:        s.opts.Tool,
		Version:     s.opts.Version,
		GeneratedAt: time.Now(),
		Roots:       req.Paths,
		Masked:      !req.ShowFull,
		Duration:    time.Since(start).Round(time.Millisecond).String(),
		Stats:       stats,
		Findings:    findings,
	}

	// Always persist GUI scans to the per-user data folder — non-technical
	// users should never lose results because they forgot to download.
	var savedPtr *report.SavedPaths
	saveErr := ""
	if stream != nil {
		if err := stream.Finish(s.last); err != nil && streamErr == nil {
			streamErr = err
		}
	}
	if streamErr != nil {
		saveErr = "findings log: " + streamErr.Error()
	}
	if saved, err := report.SaveDefaults(s.last); err != nil {
		saveErr = strings.TrimPrefix(saveErr+"; "+err.Error(), "; ")
	} else {
		if stream != nil && streamErr == nil {
			saved.FindingsLog = logPath
		}
		savedPtr = &saved
	}

	// The Report's fields are embedded so the response stays shape-compatible
	// with plain report JSON; saved/save_error/log_warning ride alongside.
	resp := struct {
		*report.Report
		Saved      *report.SavedPaths `json:"saved,omitempty"`
		SaveError  string             `json:"save_error,omitempty"`
		LogWarning string             `json:"log_warning,omitempty"`
	}{s.last.ForOutput(), savedPtr, saveErr, logWarning}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleProgress reports the state of the scan in flight (if any), so the
// page can show "scanning file 139 of 9,022" while /api/scan is still
// blocked on the engine. Deliberately not serialized on s.mu — that lock is
// held for the whole scan.
func (s *server) handleProgress(w http.ResponseWriter, r *http.Request) {
	s.progMu.Lock()
	p := s.prog
	s.progMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)
}

func (s *server) handleDownload(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	rep := s.last
	s.mu.Unlock()
	if rep == nil {
		http.Error(w, "no scan has run yet", http.StatusNotFound)
		return
	}
	stamp := rep.GeneratedAt.Format("20060102-150405")
	var err error
	switch r.URL.Query().Get("format") {
	case "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=privacylens-report-%s.html", stamp))
		err = report.WriteHTML(w, rep)
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=privacylens-report-%s.csv", stamp))
		err = report.WriteCSV(w, rep)
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=privacylens-report-%s.json", stamp))
		err = report.WriteJSON(w, rep)
	case "syslog":
		hostname, _ := os.Hostname()
		var lines []string
		lines, err = report.SyslogLines(rep, "cef", hostname, true)
		if err == nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=privacylens-findings-%s.log", stamp))
			for _, l := range lines {
				fmt.Fprintln(w, l)
			}
		}
	default:
		http.Error(w, "format must be html, csv, json, or syslog", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		fmt.Printf("(could not open browser automatically: %v)\n", err)
	}
}
