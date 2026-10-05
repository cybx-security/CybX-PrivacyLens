package report

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rdataback/privacylens/internal/paths"
	"github.com/rdataback/privacylens/internal/scanner"
)

// EventWriter streams scan events one line at a time while the scan is still
// running, so a log shipper (e.g. a Wazuh agent) ingests findings in a steady
// trickle instead of one massive burst when the scan ends. Wire its Finding
// method to scanner.Options.OnFindings, then call Finish once the scan is
// done to emit the trailing needs_ocr and scan_summary events.
type EventWriter struct {
	mu         sync.Mutex
	w          io.Writer
	closer     io.Closer // closed by Finish when the writer owns the file
	format     string    // "cef" or "json"
	hostname   string
	withHeader bool
	tool       string
	version    string
	mask       bool
	lines      int
	err        error // first write error; later writes become no-ops
}

// NewEventWriter streams events to w. mask hides PII values exactly as in
// reports; withHeader wraps each line in an RFC 3164 syslog header (always
// wanted for CEF files, never for bare NDJSON that Wazuh's JSON decoder
// tails). The header never includes a <PRI> tag: EventWriter targets are
// files a log shipper tails verbatim, and a leading "<133>" would keep the
// SIEM's pre-decoder from parsing the line (PRI belongs to network
// transport only — see SyslogLines). Timestamps are per-event write time.
func NewEventWriter(w io.Writer, format, tool, version string, mask, withHeader bool) (*EventWriter, error) {
	if format != "cef" && format != "json" {
		return nil, fmt.Errorf("unknown syslog format %q (use cef or json)", format)
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}
	return &EventWriter{
		w: w, format: format, hostname: hostname, withHeader: withHeader,
		tool: tool, version: version, mask: mask,
	}, nil
}

// OpenFindingsStream opens the auto-save findings log (<DataDir>/logs/
// findings.json) for appending and returns a bare-NDJSON EventWriter that
// owns the file (Finish closes it), plus the log's path.
func OpenFindingsStream(tool, version string, mask bool) (*EventWriter, string, error) {
	logPath, err := paths.FindingsLog()
	if err != nil {
		return nil, "", fmt.Errorf("cannot create logs directory: %w", err)
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, "", err
	}
	ew, err := NewEventWriter(f, "json", tool, version, mask, false)
	if err != nil {
		f.Close()
		return nil, "", err
	}
	ew.closer = f
	return ew, logPath, nil
}

// OpenFindingsStreamAt opens an arbitrary findings log path for appending
// and returns a bare-NDJSON EventWriter that owns the file. The parent
// directory is not created — for the machine-wide log that is the
// installer's job, and a missing directory should read as "not set up
// here", not spawn a stray one.
func OpenFindingsStreamAt(logPath, tool, version string, mask bool) (*EventWriter, error) {
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	ew, err := NewEventWriter(f, "json", tool, version, mask, false)
	if err != nil {
		f.Close()
		return nil, err
	}
	ew.closer = f
	return ew, nil
}

// OpenDefaultFindingsStream opens the findings event stream every scan —
// CLI or GUI — writes by default. Target selection, in order:
//
//  1. The machine-wide Insights log (sysPath, normally
//     paths.SystemFindingsLog()), whenever its directory exists — the
//     installer created it, so this machine feeds a SIEM. If it exists but
//     can't be written, that's a real problem worth a warning, and the
//     per-user log takes over so findings aren't lost.
//  2. The per-user findings log, silently, when sysPath's directory is
//     absent — a machine that never ran the installer isn't feeding a
//     SIEM, and nagging every laptop scan would teach people to ignore
//     warnings.
//
// warn is non-empty when the caller must tell the user something. The
// stream is nil (with a warning) only when no log is writable at all.
func OpenDefaultFindingsStream(sysPath, tool, version string, mask bool) (ew *EventWriter, logPath, warn string) {
	if _, err := os.Stat(filepath.Dir(sysPath)); err == nil {
		ew, err := OpenFindingsStreamAt(sysPath, tool, version, mask)
		if err == nil {
			return ew, sysPath, ""
		}
		warn = fmt.Sprintf("cannot write the Insights findings log (%v) — using the per-user log; Insights will NOT see this scan", err)
	}
	ew, logPath, err := OpenFindingsStream(tool, version, mask)
	if err != nil {
		if warn != "" {
			warn += "; "
		}
		return nil, "", warn + fmt.Sprintf("could not open findings log: %v", err)
	}
	return ew, logPath, warn
}

// Finding writes one finding event immediately. Safe for concurrent use;
// after a write error it becomes a no-op and Finish reports the error.
func (ew *EventWriter) Finding(f scanner.Finding) {
	if ew.mask {
		f = MaskFinding(f)
	}
	ew.writeFinding(f)
}

// Findings writes a batch of finding events; its signature matches
// scanner.Options.OnFindings. The batch — one file's findings — is masked
// as a unit so findings sharing a line hide each other's values too.
func (ew *EventWriter) Findings(fs []scanner.Finding) {
	if ew.mask {
		fs = MaskFindings(fs)
	}
	for _, f := range fs {
		ew.writeFinding(f)
	}
}

// writeFinding renders and emits one already-masked (or full-disclosure)
// finding.
func (ew *EventWriter) writeFinding(f scanner.Finding) {
	now := time.Now()
	line, err := findingLine(ew.format, ew.tool, ew.version, now.Format(time.RFC3339), ew.hostname, ew.mask, f)
	ew.emit(line, now, err)
}

// Finish emits one needs_ocr event per unsearchable document and the final
// scan_summary event from the completed report, closes the file if this
// writer owns it, and returns the first error encountered over the whole
// stream. The report's findings have already been streamed individually, so
// only the trailing events are written here.
func (ew *EventWriter) Finish(r *Report) error {
	now := time.Now()
	ts := now.Format(time.RFC3339)
	for _, path := range r.Stats.NeedOCR {
		line, err := ocrLine(ew.format, ew.tool, ew.version, ts, ew.hostname, path)
		ew.emit(line, now, err)
	}
	line, err := summaryLine(ew.format, r, ts, ew.hostname)
	ew.emit(line, now, err)

	ew.mu.Lock()
	defer ew.mu.Unlock()
	if ew.closer != nil {
		if cerr := ew.closer.Close(); ew.err == nil {
			ew.err = cerr
		}
		ew.closer = nil
	}
	return ew.err
}

// Abort closes the underlying file (when owned) without writing the
// trailing events — for when the scan itself failed and there is no
// meaningful summary to record.
func (ew *EventWriter) Abort() {
	ew.mu.Lock()
	defer ew.mu.Unlock()
	if ew.closer != nil {
		ew.closer.Close()
		ew.closer = nil
	}
}

// Lines returns how many event lines have been written so far.
func (ew *EventWriter) Lines() int {
	ew.mu.Lock()
	defer ew.mu.Unlock()
	return ew.lines
}

// emit writes one rendered line, recording the first error and dropping all
// output after it (a broken stream target won't get partial garbage).
func (ew *EventWriter) emit(payload string, t time.Time, renderErr error) {
	ew.mu.Lock()
	defer ew.mu.Unlock()
	if ew.err != nil {
		return
	}
	if renderErr != nil {
		ew.err = renderErr
		return
	}
	if ew.withHeader {
		payload = syslogHeader(ew.hostname, t) + payload
	}
	if _, err := fmt.Fprintln(ew.w, payload); err != nil {
		ew.err = err
		return
	}
	ew.lines++
}
