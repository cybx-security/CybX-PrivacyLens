package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/rdataback/privacylens/internal/extract"
)

// The `privacylens status` subcommand: a plain-language health check of an
// installation, answering "is it set up, is it scanning, and are findings
// reaching Insights?" without anyone having to know where to look.

// agentState is what could be learned about the local Insights (Wazuh)
// agent: whether one is installed and whether it tails the findings log.
type agentState struct {
	found    bool
	watching bool
	summary  string
}

// agentConfigs are where the Insights agent keeps its configuration.
var agentConfigs = []string{
	`C:\Program Files (x86)\ossec-agent\ossec.conf`,
	`C:\Program Files\ossec-agent\ossec.conf`,
	"/var/ossec/etc/ossec.conf",
	"/Library/Ossec/etc/ossec.conf",
}

// checkInsightsAgent looks for the agent's config and whether it mentions
// the findings log.
func checkInsightsAgent(logPath string) agentState {
	return checkAgentConfigs(agentConfigs, logPath)
}

func checkAgentConfigs(configs []string, logPath string) agentState {
	for _, conf := range configs {
		if _, err := os.Stat(conf); err != nil {
			continue
		}
		b, err := os.ReadFile(conf)
		if err != nil {
			return agentState{found: true, summary: "agent installed; could not read its settings to check (run as administrator)"}
		}
		// Windows paths compare case-insensitively, and people type them
		// with either slash.
		norm := func(s string) string { return strings.ToLower(strings.ReplaceAll(s, `\`, "/")) }
		if strings.Contains(norm(string(b)), norm(logPath)) {
			return agentState{found: true, watching: true, summary: "agent installed and watching the findings log"}
		}
		return agentState{found: true, summary: "agent installed but NOT watching the findings log yet"}
	}
	return agentState{summary: "no agent on this computer - findings stay in the local log"}
}

// lastScan is the most recent scan_summary event in a findings log.
type lastScan struct {
	Timestamp    string `json:"timestamp"`
	Version      string `json:"version"`
	Findings     int    `json:"findings"`
	FilesScanned int    `json:"files_scanned"`
}

// readLastScan finds the newest scan_summary in the findings log, reading
// only the tail of the file — the log is append-only and can grow large.
func readLastScan(logPath string) (*lastScan, error) {
	f, err := os.Open(logPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	const tail = 1 << 20
	if fi, err := f.Stat(); err == nil && fi.Size() > tail {
		if _, err := f.Seek(-tail, io.SeekEnd); err != nil {
			return nil, err
		}
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	lines := bytes.Split(b, []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		if !bytes.Contains(lines[i], []byte(`"privacylens_event":"scan_summary"`)) {
			continue
		}
		var s lastScan
		if json.Unmarshal(lines[i], &s) == nil {
			return &s, nil
		}
	}
	return nil, nil
}

// scheduleRegistered reports whether the weekly scan is registered with the
// platform's scheduler.
func scheduleRegistered() bool {
	switch runtime.GOOS {
	case "windows":
		return execCmd("schtasks", "/Query", "/TN", taskName) == nil
	case "darwin":
		_, err := os.Stat(launchdPlistPath)
		return err == nil
	}
	return execCmd("systemctl", "is-enabled", "privacylens.timer") == nil
}

func runStatus(args []string) int {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "Usage:\n  privacylens status\n\nShows whether PrivacyLens is installed, scheduled, and reporting on this computer.")
		return exitError
	}
	return status(resolveInstallPaths(), os.Stdout)
}

func status(p installPaths, w io.Writer) int {
	problems := 0
	row := func(ok bool, label, detail string) {
		mark := "ok  "
		if !ok {
			mark = "FIX "
			problems++
		}
		fmt.Fprintf(w, "  %s %-14s %s\n", mark, label, detail)
	}
	info := func(label, detail string) { fmt.Fprintf(w, "  --   %-14s %s\n", label, detail) }

	fmt.Fprintf(w, "%s %s - status of this computer\n\n", toolName, version)

	if _, err := os.Stat(p.binPath); err != nil {
		row(false, "Program", "not installed at "+p.binPath+" - run: privacylens install")
	} else {
		row(true, "Program", p.binPath)
	}
	if p.legacyBin != "" {
		if _, err := os.Stat(p.legacyBin); err == nil {
			row(false, "Old copy", p.legacyBin+" is left over from an older version - re-run: privacylens install")
		}
	}

	if cfg, err := loadConfig(p.manifest); err != nil {
		if os.IsNotExist(unwrapAll(err)) {
			row(false, "Scan settings", "missing: "+p.manifest+" - run: privacylens install")
		} else {
			row(false, "Scan settings", fmt.Sprintf("%s has a problem: %v", p.manifest, err))
		}
	} else {
		missing := 0
		for _, root := range cfg.Paths {
			if _, err := os.Stat(root); err != nil {
				missing++
			}
		}
		detail := p.manifest + " - scans: " + strings.Join(cfg.Paths, ", ")
		switch {
		case len(cfg.Paths) == 0:
			row(false, "Scan settings", p.manifest+" lists no folders to scan")
		case missing > 0:
			row(false, "Scan settings", detail+fmt.Sprintf(" (%d of these do not exist here)", missing))
		default:
			row(true, "Scan settings", detail)
		}
	}

	switch {
	case scheduleRegisteredFn():
		row(true, "Weekly scan", "scheduled, Sundays 02:00 ("+scheduleName()+")")
	case runtime.GOOS == "windows" && !isElevated():
		// Windows hides SYSTEM tasks from standard accounts, so "not found"
		// here proves nothing — don't cry wolf.
		info("Weekly scan", "cannot be checked from a standard account - run status from an administrator prompt")
	default:
		row(false, "Weekly scan", "not scheduled - run: privacylens install")
	}

	switch last, err := readLastScan(p.logPath); {
	case err != nil && os.IsNotExist(err):
		info("Last scan", "none yet - no findings log at "+p.logPath)
	case err != nil:
		info("Last scan", fmt.Sprintf("unknown - cannot read %s (%v)", p.logPath, err))
	case last == nil:
		info("Last scan", "none recorded yet in "+p.logPath)
	default:
		when := last.Timestamp
		stale := false
		if t, err := time.Parse(time.RFC3339, last.Timestamp); err == nil {
			age := time.Since(t)
			when = fmt.Sprintf("%s (%s ago)", t.Local().Format("Mon Jan 2 2006 15:04"), roughAge(age))
			stale = age > 9*24*time.Hour
		}
		detail := fmt.Sprintf("%s - %d finding(s) in %d file(s)", when, last.Findings, last.FilesScanned)
		if stale {
			row(false, "Last scan", detail+" - more than a week old; was this computer off on Sunday night?")
		} else {
			row(true, "Last scan", detail)
		}
	}

	if f, err := os.OpenFile(p.logPath, os.O_APPEND|os.O_WRONLY, 0); err == nil {
		f.Close()
		row(true, "Findings log", p.logPath)
	} else if os.IsNotExist(err) {
		info("Findings log", p.logPath+" (created by the first scan)")
	} else {
		info("Findings log", p.logPath+" - not writable by this account, so scans you run by hand use your per-user log")
	}

	if img, pdf := extract.HaveOCR(); img && pdf {
		row(true, "OCR", "ready (images and scanned PDFs)")
	} else if img {
		info("OCR", "images only - scanned PDFs need poppler (pdftoppm)")
	} else {
		info("OCR", "not installed - scanned documents are listed as needing OCR")
	}

	agent := checkInsightsAgent(p.logPath)
	if agent.found && !agent.watching && !strings.Contains(agent.summary, "could not read") {
		row(false, "Insights", agent.summary+" - add the <localfile> block from deploy/insights/agent-ossec.conf-snippet.xml")
	} else if agent.watching {
		row(true, "Insights", agent.summary)
	} else {
		info("Insights", agent.summary)
	}

	if problems == 0 {
		fmt.Fprintln(w, "\nEverything looks good.")
		return exitClean
	}
	fmt.Fprintf(w, "\n%d item(s) marked FIX need attention.\n", problems)
	return exitFindings
}

// unwrapAll returns the innermost wrapped error.
func unwrapAll(err error) error {
	for {
		u, ok := err.(interface{ Unwrap() error })
		if !ok || u.Unwrap() == nil {
			return err
		}
		err = u.Unwrap()
	}
}

// roughAge renders a duration the way a person would say it.
func roughAge(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}
