// Command privacylens scans directories for personally identifiable
// information (SSNs, credit cards, medical identifiers, and more) and reports
// where each item was found, with masked context.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rdataback/privacylens/internal/buildinfo"
	"github.com/rdataback/privacylens/internal/detect"
	"github.com/rdataback/privacylens/internal/extract"
	"github.com/rdataback/privacylens/internal/gui"
	"github.com/rdataback/privacylens/internal/paths"
	"github.com/rdataback/privacylens/internal/report"
	"github.com/rdataback/privacylens/internal/scanner"
)

const (
	toolName = buildinfo.Tool
	version  = buildinfo.Version
)

// Exit codes: 0 = clean, 1 = PII found, 2 = usage or runtime error.
const (
	exitClean    = 0
	exitFindings = 1
	exitError    = 2
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	if len(os.Args) > 1 && os.Args[1] == extract.PDFChildArg {
		os.Exit(extract.RunPDFChild(os.Args[2:]))
	}
	extract.EnablePDFIsolation()
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "gui":
			os.Exit(runGUI(os.Args[2:]))
		case "install":
			os.Exit(runInstall(os.Args[2:]))
		case "uninstall":
			os.Exit(runUninstall(os.Args[2:]))
		case "status":
			os.Exit(runStatus(os.Args[2:]))
		}
	}
	os.Exit(run())
}

// runGUI starts the browser-based interface (privacylens gui).
func runGUI(args []string) int {
	fs := flag.NewFlagSet("gui", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:0", "listen `address` (loopback only; port 0 picks a free port)")
	noOpen := fs.Bool("no-open", false, "do not open the browser automatically")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n  privacylens gui [flags]\n\nStarts the local web interface.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if !strings.HasPrefix(*addr, "127.") && !strings.HasPrefix(*addr, "localhost:") && !strings.HasPrefix(*addr, "[::1]:") {
		fmt.Fprintln(os.Stderr, "error: the GUI only listens on loopback addresses (127.0.0.1, localhost, or ::1)")
		return exitError
	}
	if err := gui.Run(gui.Options{
		Addr:        *addr,
		OpenBrowser: !*noOpen,
		Tool:        toolName,
		Version:     version,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	return exitClean
}

func run() int {
	var excludes multiFlag
	var excludeEmails multiFlag
	configPath := flag.String("config", "", "load scan settings from a JSON manifest `file` (or set PRIVACYLENS_CONFIG); explicit flags override it")
	jsonOut := flag.String("json", "", "write JSON report to `file`")
	csvOut := flag.String("csv", "", "write CSV report to `file`")
	htmlOut := flag.String("html", "", "write HTML report to `file`")
	syslogOut := flag.String("syslog-out", "", "write one syslog line per finding to `file` (\"-\" for stdout)")
	syslogAddr := flag.String("syslog-addr", "", "send findings to a syslog receiver at `udp://host:514` or tcp://host:514")
	syslogFormat := flag.String("syslog-format", "cef", "syslog payload: cef, or json (file output is bare NDJSON for Insights)")
	showFull := flag.Bool("show-full", false, "show complete PII values in all output (default: masked)")
	maxSizeMB := flag.Int64("max-size", 50, "skip files larger than `MB` megabytes")
	includeCloud := flag.Bool("include-cloud", false, "scan cloud-placeholder files (OneDrive/iCloud online-only); forces each one to download")
	scanAll := flag.Bool("scan-all", false, "also scan built-in skipped folders (AppData, $Recycle.Bin, node_modules, .Trash, .cache)")
	ocr := flag.Bool("ocr", false, "OCR image files and scanned PDFs with tesseract (PDFs also need pdftoppm from poppler); slow — seconds per page")
	mailOnly := flag.Bool("mail", false, "targeted mail scan: only Outlook mail stores (.pst/.ost) are opened, message by message; walks AppData, where Outlook keeps the live .ost (max-size defaults to 50 GB in this mode)")
	workers := flag.Int("workers", runtime.NumCPU(), "concurrent scan workers")
	memoryMB := flag.Int64("memory-budget", 256, "approximate aggregate `MB` allowed for files being extracted concurrently")
	categories := flag.String("categories", "", "only look for these PII `types`, comma-separated (default: all). Types: "+strings.Join(detect.Categories(), ", "))
	minConf := flag.String("min-confidence", "low", "minimum confidence to report: low, medium, or high")
	noSave := flag.Bool("no-save", false, "do not auto-save reports to the PrivacyLens data folder (auto-save is on unless -json/-csv/-html is given)")
	noFindingsLog := flag.Bool("no-findings-log", false, "do not stream findings to the Insights log (every scan appends to "+paths.SystemFindingsLog()+" when it exists, else the per-user log)")
	quiet := flag.Bool("quiet", false, "suppress console output (exit code still reflects findings)")
	verbose := flag.Bool("verbose", false, "also list files that could not be read")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Var(&excludes, "exclude", "exclude files/dirs matching `pattern` (glob on name or substring of path; repeatable)")
	flag.Var(&excludeEmails, "exclude-email", "ignore this `email` in Email Address findings — exact (info@x.com) or whole domain (@x.com); repeatable, commas OK")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `%s v%s — find PII on disk before someone else does.

Usage:
  privacylens [flags] <path> [<path>...]
  privacylens gui [-addr 127.0.0.1:0] [-no-open]
  privacylens install [-no-ocr]     set up this computer (needs admin rights)
  privacylens status                check that the installation is healthy
  privacylens uninstall [-purge]    remove it again

Scans the given files and directories for SSNs, credit cards, driver's
licenses, medical identifiers (HIPAA), bank details, and other PII, then
reports the file, location, category, and masked context of every hit.
"privacylens gui" starts the local web interface. "privacylens install"
sets up the program, scan manifest, weekly scheduled scan, and OCR tools.

Flags:
`, toolName, version)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Exit codes:
  0  scan completed, no PII found
  1  scan completed, PII found
  2  usage or runtime error

Examples:
  privacylens ~/Documents
  privacylens -html report.html -json report.json /shared/finance
  privacylens -min-confidence high -exclude node_modules -exclude '*.bak' .
  privacylens -categories "SSN,Credit Card,Email Address" ~/Documents
  privacylens -mail C:\Users            (scan Outlook .pst/.ost mailboxes only)
  privacylens -syslog-addr udp://insights.example.com:514 /data
  privacylens -syslog-out /var/log/privacylens/findings.json -syslog-format json /data
`)
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("%s v%s\n", toolName, version)
		return exitClean
	}

	// Apply the manifest, if any. Explicit command-line flags always win;
	// list values (paths from args, excludes) merge with the file's.
	if *configPath == "" {
		*configPath = os.Getenv("PRIVACYLENS_CONFIG")
	}
	roots := flag.Args()
	sizeFromConfig := false
	var manifestCats []string
	if *configPath != "" {
		cfg, err := loadConfig(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return exitError
		}
		explicit := map[string]bool{}
		flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
		useStr := func(name string, dst *string, v string) {
			if !explicit[name] && v != "" {
				*dst = v
			}
		}
		useStr("json", jsonOut, cfg.JSON)
		useStr("csv", csvOut, cfg.CSV)
		useStr("html", htmlOut, cfg.HTML)
		useStr("syslog-out", syslogOut, cfg.SyslogOut)
		useStr("syslog-addr", syslogAddr, cfg.SyslogAddr)
		useStr("syslog-format", syslogFormat, cfg.SyslogFormat)
		useStr("min-confidence", minConf, cfg.MinConfidence)
		if !explicit["max-size"] && cfg.MaxSizeMB != nil {
			*maxSizeMB = *cfg.MaxSizeMB
			sizeFromConfig = true
		}
		if !explicit["workers"] && cfg.Workers != nil {
			*workers = *cfg.Workers
		}
		if !explicit["memory-budget"] && cfg.MemoryBudgetMB != nil {
			*memoryMB = *cfg.MemoryBudgetMB
		}
		if !explicit["show-full"] && cfg.ShowFull != nil {
			*showFull = *cfg.ShowFull
		}
		if !explicit["include-cloud"] && cfg.IncludeCloud != nil {
			*includeCloud = *cfg.IncludeCloud
		}
		if !explicit["scan-all"] && cfg.ScanAll != nil {
			*scanAll = *cfg.ScanAll
		}
		if !explicit["ocr"] && cfg.OCR != nil {
			*ocr = *cfg.OCR
		}
		if !explicit["mail"] && cfg.Mail != nil {
			*mailOnly = *cfg.Mail
		}
		if !explicit["quiet"] && cfg.Quiet != nil {
			*quiet = *cfg.Quiet
		}
		if !explicit["verbose"] && cfg.Verbose != nil {
			*verbose = *cfg.Verbose
		}
		if !explicit["no-findings-log"] && cfg.NoFindingsLog != nil {
			*noFindingsLog = *cfg.NoFindingsLog
		}
		if !explicit["categories"] {
			manifestCats = cfg.Categories
		}
		excludes = append(excludes, cfg.Excludes...)
		excludeEmails = append(excludeEmails, cfg.ExcludeEmails...)
		if len(roots) == 0 {
			roots = cfg.Paths
		}
	}
	if len(roots) == 0 {
		flag.Usage()
		return exitError
	}
	// Flag parsing stops at the first path, so "privacylens C:\data -html
	// r.html" would treat -html as a folder to scan. Say what went wrong
	// instead of "cannot access -html".
	for _, r := range roots {
		if strings.HasPrefix(r, "-") {
			if _, err := os.Stat(r); err != nil {
				fmt.Fprintf(os.Stderr, "error: %q came after a path — flags must come before the paths to scan (privacylens [flags] <path>...)\n", r)
				return exitError
			}
		}
	}
	if *memoryMB < 1 {
		fmt.Fprintln(os.Stderr, "invalid -memory-budget (must be at least 1 MB)")
		return exitError
	}
	conf, ok := detect.ParseConfidence(*minConf)
	if !ok {
		fmt.Fprintf(os.Stderr, "invalid -min-confidence %q (use low, medium, or high)\n", *minConf)
		return exitError
	}

	// Category restriction: the explicit flag wins, else the manifest.
	// Names are validated up front — a typo must kill the run, not quietly
	// scan for nothing.
	catList := manifestCats
	if *categories != "" {
		catList = nil
		for _, c := range strings.Split(*categories, ",") {
			if t := strings.TrimSpace(c); t != "" {
				catList = append(catList, t)
			}
		}
	}
	if len(catList) > 0 {
		var err error
		if catList, err = detect.NormalizeCategories(catList); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return exitError
		}
	}

	// Mail stores are multi-gigabyte files; the regular 50 MB default would
	// silently skip every one. An explicit -max-size (flag or manifest)
	// still wins.
	explicitSize := sizeFromConfig
	flag.Visit(func(f *flag.Flag) { explicitSize = explicitSize || f.Name == "max-size" })
	if *mailOnly && !explicitSize {
		*maxSizeMB = 50 * 1024
	}

	if *ocr {
		extract.SetOCR(true)
		imgOK, pdfOK := extract.HaveOCR()
		switch {
		case !imgOK:
			fmt.Fprintln(os.Stderr, "warning: -ocr requested but tesseract was not found; image documents will be flagged as needing OCR, not read (install tesseract or set PRIVACYLENS_TESSERACT)")
		case !pdfOK:
			fmt.Fprintln(os.Stderr, "warning: pdftoppm (poppler) was not found; images will be OCR'd but scanned PDFs will only be flagged (install poppler or set PRIVACYLENS_PDFTOPPM)")
		}
	}

	// Outputs come in two classes. Report files (-json/-csv/-html) are the
	// user taking control of the archive, so they replace auto-save. The
	// findings EVENT stream is independent of all of that: EVERY scan
	// appends to the machine-wide Insights log (when the installer set it
	// up) no matter which report flags were used, unless an explicit event
	// destination (-syslog-out/-syslog-addr) or -no-findings-log overrides
	// it. A scan must never miss the SIEM just because someone ran it "the
	// wrong way".
	reportOutputs := *jsonOut != "" || *csvOut != "" || *htmlOut != ""
	autoSave := !reportOutputs && !*noSave

	// Fail on an unwritable report destination now, not after an hours-long
	// scan has finished with nowhere to put its results.
	for _, out := range []string{*jsonOut, *csvOut, *htmlOut} {
		if out == "" {
			continue
		}
		dir := filepath.Dir(out)
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			fmt.Fprintf(os.Stderr, "error: cannot write %s: folder %s does not exist\n", out, dir)
			return exitError
		}
	}

	// Open the event stream BEFORE scanning: findings are written as each
	// file completes, so a log shipper tailing the output (e.g. a Wazuh
	// agent) ingests a steady trickle during the scan instead of one huge
	// burst at the end. The stream target is the -syslog-out destination,
	// or the default findings log.
	var stream *report.EventWriter
	streamLogPath := ""
	if *syslogOut != "" {
		out := os.Stdout
		if *syslogOut != "-" {
			// Create the log directory if needed (e.g. /var/log/privacylens
			// on a machine that never ran the installer), so a first manual
			// run doesn't fail on a missing parent.
			if dir := filepath.Dir(*syslogOut); dir != "" && dir != "." {
				if err := os.MkdirAll(dir, 0o750); err != nil {
					fmt.Fprintf(os.Stderr, "error: cannot create log directory %s: %v\n", dir, err)
					return exitError
				}
			}
			// Append, don't truncate: scheduled runs feed a log shipper
			// that tails this file for new lines.
			f, err := os.OpenFile(*syslogOut, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: cannot write %s: %v\n", *syslogOut, err)
				return exitError
			}
			defer f.Close()
			out = f
		}
		var err error
		// File output: JSON stays bare NDJSON so Wazuh's JSON decoder can
		// parse it; CEF gets the RFC 3164 header (its program_name is what
		// the shipped decoders key on) but never a <PRI> tag — that is
		// network framing a tailed file must not contain.
		stream, err = report.NewEventWriter(out, *syslogFormat, toolName, version, !*showFull, *syslogFormat != "json")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return exitError
		}
	} else if *syslogAddr == "" && !*noFindingsLog {
		var warn string
		stream, streamLogPath, warn = report.OpenDefaultFindingsStream(paths.SystemFindingsLog(), toolName, version, !*showFull)
		if warn != "" {
			fmt.Fprintf(os.Stderr, "warning: %s\n", warn)
		}
	}

	scanOpts := scanner.Options{
		Excludes:          excludes,
		ExcludeEmails:     excludeEmails,
		MaxSizeBytes:      *maxSizeMB * 1024 * 1024,
		Workers:           *workers,
		MemoryBudgetBytes: *memoryMB * 1024 * 1024,
		MinConfidence:     conf,
		Categories:        catList,
		IncludeCloud:      *includeCloud,
		ScanAll:           *scanAll,
		MailOnly:          *mailOnly,
	}
	if stream != nil {
		scanOpts.OnFindings = stream.Findings
	}
	// Live progress on stderr when a human is watching, so a long scan is
	// distinguishable from a hang. Never on for -quiet or redirected stderr,
	// so piped/scheduled runs stay clean.
	var progress *progressLine
	if !*quiet && stderrIsTerminal() {
		progress = &progressLine{}
		scanOpts.Progress = progress.update
	}

	start := time.Now()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	findings, stats, err := scanner.ScanContext(ctx, roots, scanOpts)
	if progress != nil {
		progress.clear()
	}
	if err != nil {
		if stream != nil {
			stream.Abort()
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}

	rep := &report.Report{
		Tool:        toolName,
		Version:     version,
		GeneratedAt: time.Now(),
		Roots:       roots,
		Masked:      !*showFull,
		Duration:    time.Since(start).Round(time.Millisecond).String(),
		Stats:       stats,
		Findings:    findings,
	}

	type output struct {
		path  string
		write func(*os.File) error
	}
	outputs := []output{}
	if *jsonOut != "" {
		outputs = append(outputs, output{*jsonOut, func(f *os.File) error { return report.WriteJSON(f, rep) }})
	}
	if *csvOut != "" {
		outputs = append(outputs, output{*csvOut, func(f *os.File) error { return report.WriteCSV(f, rep) }})
	}
	if *htmlOut != "" {
		outputs = append(outputs, output{*htmlOut, func(f *os.File) error { return report.WriteHTML(f, rep) }})
	}
	// An output that fails is reported and remembered, but never stops the
	// remaining outputs: the scan is done, and every destination that CAN
	// take the results — above all the event stream's scan_summary, which
	// tells the SIEM this scan ran — still gets them. The exit code reports
	// the failure at the end.
	failed := false
	for _, o := range outputs {
		f, err := os.Create(o.path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot write %s: %v\n", o.path, err)
			failed = true
			continue
		}
		werr := o.write(f)
		cerr := f.Close()
		if werr == nil {
			werr = cerr
		}
		if werr != nil {
			fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", o.path, werr)
			failed = true
			continue
		}
		if !*quiet {
			fmt.Printf("Wrote %s\n", o.path)
		}
	}

	// Close out the stream: trailing needs_ocr + scan_summary events, plus
	// any write error accumulated while streaming during the scan.
	if stream != nil {
		if err := stream.Finish(rep); err != nil {
			target := *syslogOut
			if target == "" {
				target = streamLogPath
			}
			fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", target, err)
			failed = true
		} else if !*quiet && *syslogOut != "" && *syslogOut != "-" {
			fmt.Printf("Wrote %s (%d syslog lines)\n", *syslogOut, stream.Lines())
		} else if !*quiet && streamLogPath != "" {
			fmt.Printf("Appended events: %s\n", streamLogPath)
		}
	}

	if *syslogAddr != "" {
		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "localhost"
		}
		lines, err := report.SyslogLines(rep, *syslogFormat, hostname, true)
		if err == nil {
			err = report.SendSyslog(*syslogAddr, lines)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: syslog delivery to %s failed: %v\n", *syslogAddr, err)
			failed = true
		} else if !*quiet {
			fmt.Printf("Sent %d events to %s\n", len(lines), *syslogAddr)
		}
	}

	// No report files requested anywhere (flags or manifest): auto-save to
	// the per-user data folder so results are never lost. Explicit -json/
	// -csv/-html mean the user has taken control of the archive; syslog
	// streaming alone does not. -no-save opts out for scripting. Findings
	// were already streamed to the log during the scan (when no other
	// stream target was set).
	if autoSave {
		saved, err := report.SaveDefaults(rep)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not auto-save results: %v\n", err)
		} else if !*quiet {
			fmt.Printf("Saved report: %s\n", saved.HTML)
			fmt.Printf("Saved report: %s\n", saved.JSON)
		}
	}

	if !*quiet {
		report.PrintConsole(os.Stdout, rep, *verbose)
	}
	if failed {
		return exitError
	}
	if len(findings) > 0 {
		return exitFindings
	}
	return exitClean
}
