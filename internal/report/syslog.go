package report

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/rdataback/privacylens/internal/scanner"
)

// cefVendor is the CEF "device vendor" header field — the company shipping
// the product — present in every CEF event.
const cefVendor = "CybX"

// Syslog/CEF rendering for SIEM ingestion (Wazuh, Splunk, ArcSight, etc).
//
// Two payload formats:
//   - "cef":  ArcSight Common Event Format, one event per finding, wrapped in
//     an RFC 3164 syslog header. Wazuh and most SIEMs decode CEF natively.
//   - "json": one JSON object per finding. Written to a file this is pure
//     NDJSON (what Wazuh's <log_format>json</log_format> expects); sent over
//     the network it gets the syslog header so the receiver can route it.
//
// The <PRI> tag (e.g. "<133>") is wire framing: it is prepended only on
// network transport, where the receiving syslog listener strips it. File
// output never includes it — agents tail files verbatim, and a leading PRI
// keeps SIEM pre-decoders from parsing the line at all.

// SyslogLines renders the scan as one event per line: every finding, one
// "needs_ocr" event per document that could not be searched (no text layer),
// and a final "scan_summary" event carrying the run's totals — so the SIEM
// sees coverage gaps and scan heartbeats, not just hits. withHeader wraps
// each line in full network framing — <PRI> tag plus RFC 3164 header — and
// is only for network transport, where the receiver strips the PRI. Lines
// destined for a file must use EventWriter instead, which never writes PRI.
func SyslogLines(r *Report, format, hostname string, withHeader bool) ([]string, error) {
	if format != "cef" && format != "json" {
		return nil, fmt.Errorf("unknown syslog format %q (use cef or json)", format)
	}
	out := r.ForOutput()
	ts := out.GeneratedAt.Format(time.RFC3339)
	lines := make([]string, 0, len(out.Findings)+len(out.Stats.NeedOCR)+1)

	emit := func(payload, confidence string) {
		if withHeader {
			payload = syslogPRI(confidence) + syslogHeader(hostname, out.GeneratedAt) + payload
		}
		lines = append(lines, payload)
	}

	for _, f := range out.Findings {
		l, err := findingLine(format, out.Tool, out.Version, ts, hostname, out.Masked, f)
		if err != nil {
			return nil, err
		}
		emit(l, f.Confidence)
	}

	for _, path := range out.Stats.NeedOCR {
		l, err := ocrLine(format, out.Tool, out.Version, ts, hostname, path)
		if err != nil {
			return nil, err
		}
		emit(l, "medium")
	}

	l, err := summaryLine(format, out, ts, hostname)
	if err != nil {
		return nil, err
	}
	emit(l, "")
	return lines, nil
}

// findingLine renders one finding event in the given payload format. The
// finding is emitted as-is: masking, when wanted, is the caller's job.
func findingLine(format, tool, version, ts, hostname string, masked bool, f scanner.Finding) (string, error) {
	if format == "cef" {
		return cefLine(tool, version, f), nil
	}
	b, err := json.Marshal(syslogRecord{
		Timestamp:  ts,
		Host:       hostname,
		Tool:       tool,
		Version:    version,
		EventType:  "finding",
		Masked:     masked,
		CategoryID: categorySlug(f.Category),
		Finding:    f,
	})
	return string(b), err
}

func ocrLine(format, tool, version, ts, hostname, path string) (string, error) {
	if format == "cef" {
		return cefOCRLine(tool, version, path), nil
	}
	b, err := json.Marshal(ocrRecord{
		Timestamp: ts, Host: hostname, Tool: tool, Version: version,
		EventType: "needs_ocr", Path: path, FileName: filepath.Base(path),
	})
	return string(b), err
}

func summaryLine(format string, r *Report, ts, hostname string) (string, error) {
	if format == "cef" {
		return cefSummaryLine(r), nil
	}
	b, err := json.Marshal(summaryRecord{
		Timestamp: ts, Host: hostname, Tool: r.Tool, Version: r.Version,
		EventType: "scan_summary", Roots: r.Roots, Duration: r.Duration,
		Masked: r.Masked, Findings: len(r.Findings),
		FilesScanned: r.Stats.FilesScanned, FilesSkipped: r.Stats.FilesSkipped,
		FilesNeedOCR: r.Stats.FilesNeedOCR, FilesOCR: r.Stats.FilesOCR,
		FilesCloud: r.Stats.FilesCloud, FilesMail: r.Stats.FilesMail,
		FilesDocs: r.Stats.FilesDocs, FilesErrored: r.Stats.FilesErrored,
	})
	return string(b), err
}

// SendSyslog delivers lines to a syslog receiver. addr is udp://host:port or
// tcp://host:port. UDP sends one datagram per line; TCP uses newline framing.
func SendSyslog(addr string, lines []string) error {
	network, hostport, ok := strings.Cut(addr, "://")
	if !ok || (network != "udp" && network != "tcp") {
		return fmt.Errorf("syslog address must be udp://host:port or tcp://host:port, got %q", addr)
	}
	conn, err := net.DialTimeout(network, hostport, 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	for _, l := range lines {
		if _, err := conn.Write([]byte(l + "\n")); err != nil {
			return err
		}
	}
	return nil
}

// Every JSON record leads with tool then privacylens_event so each NDJSON
// line starts {"tool":"PrivacyLens","privacylens_event":...} — a fixed marker
// SIEM rules and humans grepping the log can key on before any variable
// fields. The event-type key is deliberately named privacylens_event, NOT
// event_type: Wazuh's stock Suricata base rule (86600) captures any JSON
// event carrying both "timestamp" and "event_type", which would silently
// swallow our events before our rules ever ran.
type syslogRecord struct {
	Tool       string `json:"tool"`
	EventType  string `json:"privacylens_event"`
	Version    string `json:"version"`
	Timestamp  string `json:"timestamp"`
	Host       string `json:"host"`
	Masked     bool   `json:"masked"`
	CategoryID string `json:"category_id"`
	scanner.Finding
}

// ocrRecord reports a document that was NOT searched because it has no text
// layer (scan/image-only) — a coverage gap the dashboard should show.
type ocrRecord struct {
	Tool      string `json:"tool"`
	EventType string `json:"privacylens_event"`
	Version   string `json:"version"`
	Timestamp string `json:"timestamp"`
	Host      string `json:"host"`
	Path      string `json:"path"`
	FileName  string `json:"file_name"`
}

// summaryRecord is the one-per-run heartbeat carrying scan totals, letting
// the SIEM distinguish "scanned clean" from "scan never ran".
type summaryRecord struct {
	Tool         string   `json:"tool"`
	EventType    string   `json:"privacylens_event"`
	Version      string   `json:"version"`
	Timestamp    string   `json:"timestamp"`
	Host         string   `json:"host"`
	Roots        []string `json:"roots"`
	Duration     string   `json:"duration"`
	Masked       bool     `json:"masked"`
	Findings     int      `json:"findings"`
	FilesScanned int      `json:"files_scanned"`
	FilesSkipped int      `json:"files_skipped"`
	FilesNeedOCR int      `json:"files_need_ocr"`
	FilesOCR     int      `json:"files_ocr"`
	// FilesCloud counts cloud placeholders (OneDrive on-demand, evicted
	// iCloud files) deliberately not read — a coverage gap the SIEM must
	// see, or "67 scanned" reads as full coverage of a mostly-cloud tree.
	FilesCloud int `json:"files_cloud_skipped"`
	// FilesMail counts Outlook stores (.pst/.ost) seen but not opened;
	// nonzero means mailboxes exist that only a -mail scan will cover.
	FilesMail int `json:"files_mail_skipped"`
	// FilesDocs counts documents in formats the scanner cannot open (old
	// .doc/.xls/.ppt, .msg, OpenDocument…) — present but never searched.
	FilesDocs    int `json:"files_unreadable_docs"`
	FilesErrored int `json:"files_errored"`
}

// syslogPRI builds the RFC 3164 <PRI> tag: facility local0, severity mapped
// from finding confidence (high=warning, medium=notice, low=info). Only
// network transport carries it — the receiver strips it on arrival. Lines
// written to a file must NOT include it: a log shipper (e.g. a Wazuh agent)
// forwards tailed lines verbatim, and a leading "<133>" stops the manager's
// pre-decoder from recognizing the syslog header, so no event decodes.
func syslogPRI(confidence string) string {
	sev := 6 // info
	switch confidence {
	case "high":
		sev = 4 // warning
	case "medium":
		sev = 5 // notice
	}
	return fmt.Sprintf("<%d>", 16*8+sev) // local0
}

// syslogHeader builds an RFC 3164 header without the <PRI> tag —
// "Jul 15 14:28:47 host privacylens: " — which is what the Wazuh
// pre-decoder expects from a tailed file and what yields
// program_name=privacylens for the shipped decoders.
func syslogHeader(hostname string, t time.Time) string {
	return fmt.Sprintf("%s %s privacylens: ", t.Format(time.Stamp), hostname)
}

// cefLine renders one finding as a CEF event. The signature ID is a stable
// category slug (e.g. "ssn", "credit-card") so SIEM rules can match on it.
func cefLine(tool, version string, f scanner.Finding) string {
	severity := 3
	switch f.Confidence {
	case "high":
		severity = 8
	case "medium":
		severity = 5
	}
	fields := []string{
		"filePath=" + cefExt(f.Path),
		"fname=" + cefExt(f.FileName),
		"cn1Label=lineNumber",
		fmt.Sprintf("cn1=%d", f.Line),
		"cs1Label=category",
		"cs1=" + cefExt(f.Category),
		"cs2Label=confidence",
		"cs2=" + cefExt(f.Confidence),
		"cs3Label=match",
		"cs3=" + cefExt(f.Match),
	}
	// Mail-store findings: cn1 is the message's position in its folder.
	if f.Folder != "" || f.Subject != "" {
		fields = append(fields,
			"cs4Label=mailFolder", "cs4="+cefExt(f.Folder),
			"cs5Label=mailSubject", "cs5="+cefExt(f.Subject))
		if f.Date != "" {
			fields = append(fields, "cs6Label=mailDate", "cs6="+cefExt(f.Date))
		}
		if f.From != "" {
			fields = append(fields, "suser="+cefExt(f.From))
		}
		if f.Attachment != "" {
			fields = append(fields, "flexString1Label=attachment", "flexString1="+cefExt(f.Attachment))
		}
	}
	ext := strings.Join(append(fields, "msg="+cefExt(f.Context)), " ")
	return fmt.Sprintf("CEF:0|%s|%s|%s|%s|PII detected: %s|%d|%s",
		cefHdr(cefVendor), cefHdr(tool), cefHdr(version), cefHdr(categorySlug(f.Category)),
		cefHdr(f.Category), severity, ext)
}

// cefOCRLine renders a not-searched document as a CEF event (severity 5:
// worth review — the file may hold PII nothing has looked at).
func cefOCRLine(tool, version, path string) string {
	ext := strings.Join([]string{
		"filePath=" + cefExt(path),
		"fname=" + cefExt(filepath.Base(path)),
		"msg=" + cefExt("Scanned/image-only document with no text layer; contents were NOT searched (needs OCR)"),
	}, " ")
	return fmt.Sprintf("CEF:0|%s|%s|%s|needs-ocr|Document not searched - needs OCR|5|%s",
		cefHdr(cefVendor), cefHdr(tool), cefHdr(version), ext)
}

// cefSummaryLine renders the per-run scan summary as a CEF event.
func cefSummaryLine(r *Report) string {
	ext := strings.Join([]string{
		fmt.Sprintf("cn1Label=findings cn1=%d", len(r.Findings)),
		fmt.Sprintf("cn2Label=filesScanned cn2=%d", r.Stats.FilesScanned),
		fmt.Sprintf("cn3Label=filesNeedOcr cn3=%d", r.Stats.FilesNeedOCR),
		"msg=" + cefExt(fmt.Sprintf("roots: %s; duration %s; skipped %d; cloud-skipped %d; mail-stores-skipped %d; unreadable-docs %d; unreadable %d",
			strings.Join(r.Roots, ", "), r.Duration, r.Stats.FilesSkipped, r.Stats.FilesCloud, r.Stats.FilesMail, r.Stats.FilesDocs, r.Stats.FilesErrored)),
	}, " ")
	return fmt.Sprintf("CEF:0|%s|%s|%s|scan-summary|PII scan completed|3|%s",
		cefHdr(cefVendor), cefHdr(r.Tool), cefHdr(r.Version), ext)
}

// cefHdr escapes CEF header fields (backslash and pipe).
func cefHdr(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, "|", `\|`)
}

// cefExt escapes CEF extension values (backslash, equals, newlines).
func cefExt(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "=", `\=`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return strings.ReplaceAll(s, "\r", `\r`)
}

func categorySlug(category string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(category) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			dash = false
		default:
			if !dash && b.Len() > 0 {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	return strings.TrimSuffix(b.String(), "-")
}
