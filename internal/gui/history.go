package gui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rdataback/privacylens/internal/paths"
	"github.com/rdataback/privacylens/internal/report"
)

// savedReportName matches the JSON reports SaveDefaults writes
// (scan-2006-01-02_150405.json). Anything else — above all anything with a
// path separator in it — is refused, so the history endpoints can only ever
// read PrivacyLens's own reports folder.
var savedReportName = regexp.MustCompile(`^scan-\d{4}-\d{2}-\d{2}_\d{6}\.json$`)

// historyEntry summarizes one saved scan for the Past scans tab.
type historyEntry struct {
	Name         string         `json:"name"` // JSON report file name
	GeneratedAt  time.Time      `json:"generated_at"`
	Version      string         `json:"version"`
	Roots        []string       `json:"roots"`
	Masked       bool           `json:"masked"`
	Duration     string         `json:"duration"`
	Findings     int            `json:"findings"`
	FilesScanned int            `json:"files_scanned"`
	Params       *report.Params `json:"params,omitempty"`
	HTML         string         `json:"html,omitempty"` // saved HTML report beside it, if present
	JSON         string         `json:"json"`
}

// reportHead is the slice of a saved report the history list needs.
// Findings decode into empty structs so a report with thousands of them
// costs a token walk, not a copy of every finding.
type reportHead struct {
	GeneratedAt time.Time `json:"generated_at"`
	Version     string    `json:"version"`
	Roots       []string  `json:"roots"`
	Masked      bool      `json:"masked"`
	Duration    string    `json:"duration"`
	Stats       struct {
		FilesScanned int `json:"files_scanned"`
	} `json:"stats"`
	Findings []struct{}     `json:"findings"`
	Params   *report.Params `json:"params"`
}

// historyCache remembers each summarized report by file size and
// modification time, so reopening the tab does not re-read every report.
type historyCache struct {
	mu      sync.Mutex
	entries map[string]cachedEntry
}

type cachedEntry struct {
	size  int64
	mtime time.Time
	entry historyEntry
}

// handleHistory lists the saved scans in the reports folder, newest first.
func (s *server) handleHistory(w http.ResponseWriter, r *http.Request) {
	dir, err := paths.ReportsDir()
	if err != nil {
		http.Error(w, "reports folder: "+err.Error(), http.StatusInternalServerError)
		return
	}
	names, err := os.ReadDir(dir)
	if err != nil {
		http.Error(w, "reports folder: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.history.mu.Lock()
	defer s.history.mu.Unlock()
	if s.history.entries == nil {
		s.history.entries = map[string]cachedEntry{}
	}
	seen := map[string]bool{}
	entries := []historyEntry{}
	for _, d := range names {
		if d.IsDir() || !savedReportName.MatchString(d.Name()) {
			continue
		}
		info, err := d.Info()
		if err != nil {
			continue
		}
		seen[d.Name()] = true
		if c, ok := s.history.entries[d.Name()]; ok && c.size == info.Size() && c.mtime.Equal(info.ModTime()) {
			entries = append(entries, c.entry)
			continue
		}
		e, err := summarizeReport(dir, d.Name())
		if err != nil {
			// A truncated or foreign file is skipped rather than hiding
			// every other scan behind an error.
			continue
		}
		s.history.entries[d.Name()] = cachedEntry{info.Size(), info.ModTime(), e}
		entries = append(entries, e)
	}
	for name := range s.history.entries {
		if !seen[name] {
			delete(s.history.entries, name)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].GeneratedAt.After(entries[j].GeneratedAt) })
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Dir     string         `json:"dir"`
		Reports []historyEntry `json:"reports"`
	}{dir, entries})
}

func summarizeReport(dir, name string) (historyEntry, error) {
	f, err := os.Open(filepath.Join(dir, name))
	if err != nil {
		return historyEntry{}, err
	}
	defer f.Close()
	var head reportHead
	if err := json.NewDecoder(f).Decode(&head); err != nil {
		return historyEntry{}, err
	}
	if head.GeneratedAt.IsZero() {
		return historyEntry{}, errors.New("not a PrivacyLens report")
	}
	e := historyEntry{
		Name: name, GeneratedAt: head.GeneratedAt, Version: head.Version,
		Roots: head.Roots, Masked: head.Masked, Duration: head.Duration,
		Findings: len(head.Findings), FilesScanned: head.Stats.FilesScanned,
		Params: head.Params, JSON: filepath.Join(dir, name),
	}
	htmlPath := strings.TrimSuffix(e.JSON, ".json") + ".html"
	if _, err := os.Stat(htmlPath); err == nil {
		e.HTML = htmlPath
	}
	return e, nil
}

// loadSavedReport reads one saved JSON report back into a Report, for
// re-rendering in the page or re-downloading in another format.
func loadSavedReport(name string) (*report.Report, error) {
	if !savedReportName.MatchString(name) {
		return nil, errors.New("not a saved report name")
	}
	dir, err := paths.ReportsDir()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var rep report.Report
	if err := json.NewDecoder(io.LimitReader(f, 1<<30)).Decode(&rep); err != nil {
		return nil, fmt.Errorf("reading %s: %w", name, err)
	}
	return &rep, nil
}

// handleHistoryReport returns one saved scan in the same shape /api/scan
// replies with, so the page renders it with the same code.
func (s *server) handleHistoryReport(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if !savedReportName.MatchString(name) {
		http.Error(w, "bad report name", http.StatusBadRequest)
		return
	}
	rep, err := loadSavedReport(name)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// Saved reports were masked when written (Report.Masked says so), so
	// they are sent as-is rather than through ForOutput.
	json.NewEncoder(w).Encode(pageReport{Report: rep, Settings: rep.Params.Lines()})
}

// pageReport is what the page renders: the Report's fields embedded so the
// response stays shape-compatible with plain report JSON, plus the settings
// spelled out as label/value rows, and the save outcome of a live scan.
type pageReport struct {
	*report.Report
	Settings   []report.ParamLine `json:"settings"`
	Saved      *report.SavedPaths `json:"saved,omitempty"`
	SaveError  string             `json:"save_error,omitempty"`
	LogWarning string             `json:"log_warning,omitempty"`
}

// guiSettings is the state of the scan form, persisted so the window opens
// the way it was left: paths, options, and which PII types were unticked.
type guiSettings struct {
	Paths         string `json:"paths"`
	Excludes      string `json:"excludes"`
	ExcludeEmails string `json:"exclude_emails"`
	MinConfidence string `json:"min_confidence"`
	MaxSizeMB     int64  `json:"max_size_mb"`
	ShowFull      bool   `json:"show_full"`
	OCR           bool   `json:"ocr"`
	IncludeCloud  bool   `json:"include_cloud"`
	ScanAll       bool   `json:"scan_all"`
	Mail          bool   `json:"mail"`
	WazuhLog      bool   `json:"wazuh_log"`
	// CategoriesOff lists the PII types the user unticked. Stored as the
	// exceptions, so a detector added in a later release is on by default
	// instead of silently missing from every scan.
	CategoriesOff []string `json:"categories_off"`
}

// settingsFile is where the form state lives: <DataDir>/gui-settings.json.
// The data folder, not browser storage: the GUI listens on a random port
// each launch, and browsers scope their storage to the port.
func settingsFile() (string, error) {
	dir, err := paths.DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "gui-settings.json"), nil
}

// handleSettings reads (GET) or replaces (PUT) the saved form state.
func (s *server) handleSettings(w http.ResponseWriter, r *http.Request) {
	path, err := settingsFile()
	if err != nil {
		http.Error(w, "settings: "+err.Error(), http.StatusInternalServerError)
		return
	}
	switch r.Method {
	case http.MethodGet:
		b, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err != nil {
			http.Error(w, "settings: "+err.Error(), http.StatusInternalServerError)
			return
		}
		var st guiSettings
		if json.Unmarshal(b, &st) != nil {
			// A damaged file is ignored, not fatal: the page falls back to
			// its defaults and the next change overwrites it.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(st)
	case http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		var st guiSettings
		if err := dec.Decode(&st); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		b, _ := json.MarshalIndent(st, "", "  ")
		s.settingsMu.Lock()
		defer s.settingsMu.Unlock()
		// Write-then-rename so a crash mid-write never leaves a half file
		// that makes the next launch forget everything.
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, b, 0o600); err == nil {
			err = os.Rename(tmp, path)
		}
		if err != nil {
			os.Remove(tmp)
			http.Error(w, "settings: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "GET or PUT required", http.StatusMethodNotAllowed)
	}
}
