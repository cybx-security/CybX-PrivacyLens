package main

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rdataback/privacylens/internal/extract"
	"github.com/rdataback/privacylens/internal/paths"
)

// The `privacylens install` subcommand: one installer for every platform.
// Run elevated/as root (on Windows it asks for elevation itself), it
//   - copies the program to the standard, admin-only location — and the
//     double-click GUI launcher too, when it sits beside the installer
//   - writes a starter scan manifest (kept if one already exists)
//   - registers the weekly scheduled scan (Task Scheduler / systemd /
//     launchd), Sundays 02:00
//   - installs the OCR tools (tesseract + poppler) via the platform's
//     package manager when one is available, and enables "ocr": true in a
//     freshly written manifest when they're usable
//   - on Windows, adds a Start Menu shortcut and an "Installed apps" entry
// `privacylens uninstall` reverses it (settings, reports, and the findings
// log are kept unless -purge is given); `privacylens status` reports
// whether an installation is healthy.

const (
	taskName           = "PrivacyLens Scan"
	launchdLabel       = "com.cybx.privacylens"
	launchdPlistPath   = "/Library/LaunchDaemons/com.cybx.privacylens.plist"
	systemdServicePath = "/etc/systemd/system/privacylens.service"
	systemdTimerPath   = "/etc/systemd/system/privacylens.timer"
	// uninstallRegKey is the Windows "Installed apps" (Add/Remove Programs)
	// entry.
	uninstallRegKey = `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\PrivacyLens`
	envRegKey       = `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
)

// installPaths resolves the per-OS install layout.
type installPaths struct {
	binDir   string // where the program lands (admin-only)
	binPath  string
	guiPath  string // installed GUI launcher (an .app bundle on macOS)
	etcDir   string // manifest directory
	manifest string
	logDir   string // findings log directory the SIEM agent tails
	logPath  string
	// legacyBin is where releases before 0.9.6 put the Windows binary: in
	// ProgramData, which ordinary users can create files under — not a safe
	// home for a program the weekly task runs as SYSTEM. Removed on upgrade.
	legacyBin string
	// shortcut is the all-users Start Menu shortcut (Windows only).
	shortcut string
	// desktopEntry is the applications-menu entry (Linux only).
	desktopEntry string
}

// The platform scheduler hooks, as variables so tests can exercise the
// whole install/uninstall flow against a temp directory without touching
// the machine's real schedule.
var (
	registerScheduleFn   = registerSchedule
	removeScheduleFn     = removeSchedule
	scheduleRegisteredFn = scheduleRegistered
)

func resolveInstallPaths() installPaths {
	var p installPaths
	p.logPath = paths.SystemFindingsLog()
	p.logDir = filepath.Dir(p.logPath)
	if runtime.GOOS == "windows" {
		data := os.Getenv("ProgramData")
		if data == "" {
			data = `C:\ProgramData`
		}
		prog := os.Getenv("ProgramW6432") // the real Program Files even from a 32-bit process
		if prog == "" {
			prog = os.Getenv("ProgramFiles")
		}
		if prog == "" {
			prog = `C:\Program Files`
		}
		p.binDir = filepath.Join(prog, "PrivacyLens")
		p.binPath = filepath.Join(p.binDir, "privacylens.exe")
		p.guiPath = filepath.Join(p.binDir, "privacylens-gui.exe")
		p.etcDir = filepath.Join(data, "PrivacyLens")
		p.manifest = filepath.Join(p.etcDir, "scan.json")
		p.legacyBin = filepath.Join(p.etcDir, "privacylens.exe")
		p.shortcut = filepath.Join(data, "Microsoft", "Windows", "Start Menu", "Programs", "PrivacyLens.lnk")
		return p
	}
	p.binDir = "/usr/local/bin"
	p.binPath = "/usr/local/bin/privacylens"
	p.guiPath = "/usr/local/bin/privacylens-gui"
	if runtime.GOOS == "darwin" {
		p.guiPath = "/Applications/PrivacyLens.app"
	}
	if runtime.GOOS == "linux" {
		p.desktopEntry = "/usr/share/applications/privacylens.desktop"
	}
	p.etcDir = "/etc/privacylens"
	p.manifest = "/etc/privacylens/scan.json"
	return p
}

// guiSource returns the GUI launcher shipped beside the running installer
// (as release packages lay it out), or "" when there is none.
func guiSource() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	name := "privacylens-gui"
	switch runtime.GOOS {
	case "windows":
		name = "privacylens-gui.exe"
	case "darwin":
		name = "PrivacyLens.app"
	}
	src := filepath.Join(filepath.Dir(exe), name)
	if _, err := os.Stat(src); err != nil {
		return ""
	}
	return src
}

// stepPrinter numbers the installer's stages so anyone watching can tell
// what is happening and how far along it is.
type stepPrinter struct{ n, total int }

func (s *stepPrinter) step(title string) {
	s.n++
	fmt.Printf("\n[%d/%d] %s\n", s.n, s.total, title)
}

func okf(format string, a ...any)   { fmt.Printf("      ok    "+format+"\n", a...) }
func notef(format string, a ...any) { fmt.Printf("      note  "+format+"\n", a...) }
func warnf(format string, a ...any) { fmt.Printf("      WARN  "+format+"\n", a...) }

// waitForEnter keeps a console window that exists only for this command
// (a double-clicked installer, an elevated relaunch) open until the user
// has read the result.
func waitForEnter() {
	fmt.Print("\nPress Enter to close this window…")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

// elevatedOrRelaunch makes sure the command runs with administrator rights.
// It returns proceed=true when it already does. Otherwise, on Windows it
// restarts itself through a UAC prompt (the work continues in that new
// window) and elsewhere it explains how to re-run under sudo.
func elevatedOrRelaunch(sub string, args []string) (proceed bool, code int) {
	if isElevated() {
		return true, exitClean
	}
	if runtime.GOOS != "windows" {
		fmt.Fprintf(os.Stderr, "error: %s needs administrator rights. Run it with sudo:\n\n  sudo privacylens %s\n", sub, strings.Join(append([]string{sub}, args...), " "))
		return false, exitError
	}
	fmt.Printf("PrivacyLens %s needs administrator permission.\nApprove the Windows prompt — the %s continues in a new window.\n", sub, sub)
	relaunch := append([]string{sub}, args...)
	if !hasFlag(args, "pause") {
		relaunch = append(relaunch, "-pause") // the new window would vanish on completion
	}
	if err := relaunchElevated(relaunch); err != nil {
		fmt.Fprintf(os.Stderr, "error: could not get administrator permission (%v).\nRight-click Command Prompt, choose \"Run as administrator\", and run: privacylens %s\n", err, sub)
		return false, exitError
	}
	return false, exitClean
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == "-"+name || a == "--"+name {
			return true
		}
	}
	return false
}

func runInstall(args []string) int {
	fset := flag.NewFlagSet("install", flag.ExitOnError)
	noOCR := fset.Bool("no-ocr", false, "skip installing the OCR tools (tesseract, poppler)")
	pause := fset.Bool("pause", false, "wait for Enter before exiting (for double-click installs)")
	fset.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage:
  privacylens install [-no-ocr] [-pause]

Installs PrivacyLens for every user of this computer: the program, a starter
scan manifest, the weekly scheduled scan (Sundays 02:00), and — unless
-no-ocr is given — the OCR tools via the system package manager. Needs
administrator rights: on Windows it asks for them itself; on Linux and
macOS run it with sudo. Safe to re-run: it upgrades in place and never
overwrites an existing manifest.

Flags:
`)
		fset.PrintDefaults()
	}
	fset.Parse(args)

	proceed, code := elevatedOrRelaunch("install", args)
	if !proceed {
		return code
	}
	code = install(resolveInstallPaths(), *noOCR)
	if *pause {
		waitForEnter()
	}
	return code
}

func install(p installPaths, noOCR bool) int {
	fail := func(format string, a ...any) int {
		fmt.Printf("\nINSTALLATION FAILED: "+format+"\nNothing above this line was undone; fix the problem and run the installer again.\n", a...)
		return exitError
	}

	_, statErr := os.Stat(p.binPath)
	upgrade := statErr == nil
	if !upgrade && p.legacyBin != "" {
		_, statErr = os.Stat(p.legacyBin)
		upgrade = statErr == nil
	}
	fmt.Printf("%s %s — installer\n", toolName, version)
	if upgrade {
		fmt.Println("An existing installation was found; it will be updated in place.")
	}
	steps := &stepPrinter{total: 5}

	steps.step("Installing the program")
	for _, dir := range []string{p.binDir, p.etcDir, p.logDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fail("cannot create %s: %v", dir, err)
		}
	}
	if runtime.GOOS == "windows" {
		secureWindowsDataDir(p)
	}
	if err := installBinary(p.binPath); err != nil {
		return fail("cannot install the program to %s: %v", p.binPath, err)
	}
	okf("%s", p.binPath)
	guiInstalled := false
	if src := guiSource(); src != "" {
		if err := installGUI(src, p.guiPath); err != nil {
			warnf("could not install the app window launcher (%v); close PrivacyLens if it is open and re-run the installer", err)
		} else {
			guiInstalled = true
			okf("%s", p.guiPath)
		}
	}
	removeLegacyBinary(p)

	// OCR tools before the manifest, so a fresh manifest can enable OCR
	// only when the tools actually work.
	steps.step("Setting up OCR (reads scanned documents and images)")
	ocrReady := false
	if noOCR {
		notef("skipped (-no-ocr); scanned documents will be listed as needing OCR")
	} else {
		ocrReady = installOCRTools()
	}

	steps.step("Writing the scan settings")
	if _, err := os.Stat(p.manifest); os.IsNotExist(err) {
		if err := writeManifest(p, ocrReady); err != nil {
			return fail("cannot write the scan settings to %s: %v", p.manifest, err)
		}
		okf("%s (new)", p.manifest)
	} else {
		okf("%s (existing settings kept)", p.manifest)
		if ocrReady {
			notef(`OCR tools are ready — set "ocr": true in that file to read scanned documents`)
		}
	}
	scanRoots := "(could not read the settings file)"
	if cfg, err := loadConfig(p.manifest); err == nil {
		scanRoots = strings.Join(cfg.Paths, ", ")
	} else {
		warnf("the settings file has a problem and the weekly scan will fail until it is fixed: %v", err)
	}

	steps.step("Scheduling the weekly scan")
	if err := registerScheduleFn(p); err != nil {
		return fail("cannot register the weekly scan: %v", err)
	}
	okf("every Sunday at 02:00 (%s)", scheduleName())

	steps.step("Finishing up")
	// The findings log is created now so the first scan by a standard user
	// only needs to append to it.
	if f, err := os.OpenFile(p.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640); err != nil {
		warnf("could not create the findings log %s: %v", p.logPath, err)
	} else {
		f.Close()
		okf("findings log: %s", p.logPath)
	}
	if runtime.GOOS == "windows" {
		finishWindowsInstall(p, guiInstalled)
	}
	if p.desktopEntry != "" && guiInstalled {
		if err := os.WriteFile(p.desktopEntry, []byte(desktopEntry), 0o644); err == nil {
			okf("application menu entry: PrivacyLens")
		}
	}
	agent := checkInsightsAgent(p.logPath)

	fmt.Printf(`
%s %s is installed.

  Program        %s
  Scan settings  %s
  Folders        %s
  Weekly scan    Sundays 02:00
  Findings log   %s
  OCR            %s
  Insights       %s

What to do next
`, toolName, version, p.binPath, p.manifest, scanRoots, p.logPath, ocrSummary(noOCR), agent.summary)
	for _, l := range nextSteps(p, guiInstalled, agent) {
		fmt.Println("  - " + l)
	}
	return exitClean
}

// nextSteps is the closing "what now" list: how to open the app, how to
// change what gets scanned, and how to check or remove the installation.
func nextSteps(p installPaths, gui bool, agent agentState) []string {
	var out []string
	switch {
	case runtime.GOOS == "windows":
		out = append(out, `Scan now: open "PrivacyLens" from the Start Menu.`)
	case gui && runtime.GOOS == "darwin":
		out = append(out, "Scan now: open PrivacyLens from the Applications folder.")
	case gui:
		out = append(out, "Scan now: open PrivacyLens from the applications menu, or run: privacylens gui")
	default:
		out = append(out, "Scan now: run  privacylens gui  (opens in your browser), or  privacylens <folder>")
	}
	out = append(out,
		"Change which folders the weekly scan covers: edit "+p.manifest,
		"Check that everything is working at any time: privacylens status",
	)
	if agent.found && !agent.watching {
		out = append(out, "Connect to Insights: add the findings log to the agent's ossec.conf (see deploy/insights/agent-ossec.conf-snippet.xml), then restart the agent.")
	}
	if runtime.GOOS == "windows" {
		out = append(out, `Remove it: Settings > Apps > Installed apps > PrivacyLens > Uninstall.`)
	} else {
		out = append(out, "Remove it: sudo privacylens uninstall")
	}
	return out
}

func ocrSummary(skipped bool) string {
	img, pdf := extract.HaveOCR()
	switch {
	case img && pdf:
		return "ready (images and scanned PDFs)"
	case img:
		return "images only — scanned PDFs need poppler (pdftoppm)"
	case skipped:
		return "not installed (skipped)"
	}
	return "not available — scanned documents are listed as needing OCR"
}

func scheduleName() string {
	switch runtime.GOOS {
	case "windows":
		return `Task Scheduler task "` + taskName + `", runs as SYSTEM`
	case "darwin":
		return "launchd job " + launchdLabel
	}
	return "systemd privacylens.timer"
}

// secureWindowsDataDir puts the ProgramData\PrivacyLens folder back under
// administrator control and opens the logs folder for appending. Ordinary
// users can create folders under ProgramData, so the folder may predate the
// installer and be owned by whoever made it — and it holds the manifest the
// SYSTEM task reads. Taking ownership and resetting to the inherited
// permissions leaves it exactly as a fresh admin-created folder would be.
// All best-effort: a failure costs hardening, not the installation.
func secureWindowsDataDir(p installPaths) {
	const admins = "*S-1-5-32-544" // BUILTIN\Administrators, language-independent
	if err := execCmd("icacls", p.etcDir, "/setowner", admins, "/T", "/C", "/Q"); err != nil {
		warnf("could not take ownership of %s (%v)", p.etcDir, err)
	}
	if err := execCmd("icacls", p.etcDir, "/reset", "/T", "/C", "/Q"); err != nil {
		warnf("could not reset permissions on %s (%v)", p.etcDir, err)
	}
	// Every scan — GUI or CLI, elevated or not — appends to the findings
	// log in this directory by default, so non-admin users need append
	// rights or their scans silently miss the SIEM. S-1-5-32-545 is the
	// BUILTIN\Users well-known SID. Grant only append, read-attributes,
	// and synchronization rights inherited by the log file; broad Modify
	// rights would let any user delete or rewrite SIEM evidence.
	if err := execCmd("icacls", p.logDir, "/grant", "*S-1-5-32-545:(OI)(CI)(AD,RA,REA,WEA,WA,S)"); err != nil {
		warnf("could not let standard users write to %s (%v); their scans will fall back to per-user logs", p.logDir, err)
	}
}

// removeLegacyBinary deletes the pre-0.9.6 Windows binary from ProgramData
// once the new one is in Program Files. The copy that is currently running
// cannot delete itself; it says so instead.
func removeLegacyBinary(p installPaths) {
	if p.legacyBin == "" {
		return
	}
	os.Remove(p.legacyBin + ".new")
	if _, err := os.Stat(p.legacyBin); err != nil {
		return
	}
	if exe, err := os.Executable(); err == nil {
		if same, _ := sameFilePath(exe, p.legacyBin); same {
			notef("the old copy at %s is the one running this installer; delete it afterwards", p.legacyBin)
			return
		}
	}
	if err := os.Remove(p.legacyBin); err != nil {
		warnf("could not remove the old copy at %s (%v); delete it by hand", p.legacyBin, err)
		return
	}
	okf("removed the old copy from %s", filepath.Dir(p.legacyBin))
}

// finishWindowsInstall adds what makes it a normal Windows program: a Start
// Menu shortcut and an "Installed apps" entry with a working Uninstall
// button. Best-effort — neither affects scanning.
func finishWindowsInstall(p installPaths, gui bool) {
	target, args := p.binPath, "gui"
	if gui {
		target, args = p.guiPath, ""
	}
	if err := execCmd("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", shortcutScript(p.shortcut, target, args, p.binDir)); err != nil {
		warnf("could not create the Start Menu shortcut (%v)", err)
	} else {
		okf("Start Menu shortcut: PrivacyLens")
	}
	ok := true
	for _, v := range uninstallEntryValues(p) {
		if err := execCmd("reg", "add", uninstallRegKey, "/v", v.name, "/t", v.kind, "/d", v.data, "/f"); err != nil {
			warnf(`could not register with "Installed apps" (%v)`, err)
			ok = false
			break
		}
	}
	if ok {
		okf(`listed under Settings > Apps > Installed apps`)
	}
}

// psQuote renders s as a PowerShell single-quoted string literal.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// shortcutScript is the PowerShell that writes a .lnk — there is no simpler
// dependency-free way to create one.
func shortcutScript(lnk, target, args, workDir string) string {
	return fmt.Sprintf("$s=(New-Object -ComObject WScript.Shell).CreateShortcut(%s);$s.TargetPath=%s;$s.Arguments=%s;$s.WorkingDirectory=%s;$s.Description=%s;$s.Save()",
		psQuote(lnk), psQuote(target), psQuote(args), psQuote(workDir), psQuote("Find personal data (PII) stored on this computer"))
}

type regValue struct{ name, kind, data string }

// uninstallEntryValues describes PrivacyLens to the Windows "Installed
// apps" list. The uninstall command pauses at the end because Windows runs
// it in a console window of its own.
func uninstallEntryValues(p installPaths) []regValue {
	return []regValue{
		{"DisplayName", "REG_SZ", toolName},
		{"DisplayVersion", "REG_SZ", version},
		{"Publisher", "REG_SZ", "CybX"},
		{"InstallLocation", "REG_SZ", p.binDir},
		{"DisplayIcon", "REG_SZ", p.binPath},
		{"UninstallString", "REG_SZ", `"` + p.binPath + `" uninstall -pause`},
		{"NoModify", "REG_DWORD", "1"},
		{"NoRepair", "REG_DWORD", "1"},
	}
}

func runUninstall(args []string) int {
	fset := flag.NewFlagSet("uninstall", flag.ExitOnError)
	purge := fset.Bool("purge", false, "also delete the scan settings, saved reports, and the findings log")
	pause := fset.Bool("pause", false, "wait for Enter before exiting (for double-click uninstalls)")
	fset.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage:
  privacylens uninstall [-purge] [-pause]

Removes PrivacyLens from this computer: the weekly scheduled scan, the
program, and its shortcuts. The scan settings, saved reports, and the
findings log are kept (they are your records) unless -purge is given.
The OCR tools (Tesseract, poppler) are separate programs and are left
installed. Needs administrator rights, like install.

Flags:
`)
		fset.PrintDefaults()
	}
	fset.Parse(args)

	proceed, code := elevatedOrRelaunch("uninstall", args)
	if !proceed {
		return code
	}
	p := resolveInstallPaths()
	cleanup := uninstall(p, *purge)
	if *pause {
		waitForEnter()
	}
	// Last of all: on Windows the program folder holds the very executable
	// that is running, so its removal is handed to a helper that waits for
	// this process to exit.
	if cleanup != nil {
		cleanup()
	}
	return exitClean
}

// uninstall removes the installation and returns an optional final action
// to run just before the process exits.
func uninstall(p installPaths, purge bool) (cleanup func()) {
	fmt.Printf("%s %s — uninstaller\n", toolName, version)
	steps := &stepPrinter{total: 3}
	// gone reports a removal, treating "was never there" as nothing to say.
	gone := func(what string, err error) {
		switch {
		case err == nil:
			okf("removed %s", what)
		case os.IsNotExist(err):
		default:
			warnf("could not remove %s (%v)", what, err)
		}
	}

	steps.step("Removing the weekly scan")
	removeScheduleFn(gone)
	notef("no more scheduled scans will run")

	steps.step("Removing the program")
	if runtime.GOOS == "windows" {
		gone("Start Menu shortcut", os.Remove(p.shortcut))
		execCmd("reg", "delete", uninstallRegKey, "/f")
		gone("old copy "+p.legacyBin, os.Remove(p.legacyBin))
		binDir := p.binDir
		if _, err := os.Stat(binDir); err == nil {
			cleanup = func() {
				if err := removeDirAfterExit(binDir); err != nil {
					fmt.Printf("could not remove %s (%v); delete the folder by hand\n", binDir, err)
				}
			}
			okf("%s will be removed as this window closes", binDir)
		}
	} else {
		if runtime.GOOS == "darwin" {
			gone(p.guiPath, removeAllIfExists(p.guiPath))
		} else {
			gone(p.guiPath, os.Remove(p.guiPath))
			if p.desktopEntry != "" {
				gone("application menu entry", os.Remove(p.desktopEntry))
			}
		}
		gone(p.binPath, os.Remove(p.binPath))
	}

	steps.step("Your data")
	if purge {
		gone("scan settings and data in "+p.etcDir, removeAllIfExists(p.etcDir))
		if !strings.HasPrefix(p.logDir, p.etcDir) {
			gone("findings log folder "+p.logDir, removeAllIfExists(p.logDir))
		}
	} else {
		notef("kept: scan settings  %s", p.manifest)
		notef("kept: findings log   %s", p.logPath)
		notef("kept: saved reports  (in each user's PrivacyLens data folder)")
		notef("to delete these as well, run: privacylens uninstall -purge")
	}
	notef("the OCR tools (Tesseract, poppler) were left installed; remove them separately if unwanted")

	fmt.Printf("\n%s has been uninstalled.\n", toolName)
	return cleanup
}

// removeAllIfExists is os.RemoveAll that reports a missing target as
// os.ErrNotExist, so callers can stay quiet about it.
func removeAllIfExists(path string) error {
	if _, err := os.Lstat(path); err != nil {
		return err
	}
	return os.RemoveAll(path)
}

// installBinary copies the running executable to dst (no-op when already
// running from there).
func installBinary(dst string) error {
	src, err := os.Executable()
	if err != nil {
		return err
	}
	if same, _ := sameFilePath(src, dst); same {
		return nil
	}
	if err := copyFileAtomic(src, dst); err != nil {
		return err
	}
	if runtime.GOOS == "darwin" {
		// A downloaded binary may carry the quarantine flag, which blocks
		// launchd from running it.
		execCmd("xattr", "-d", "com.apple.quarantine", dst)
	}
	return nil
}

// copyFileAtomic writes src to a temp name beside dst and renames it into
// place, so a running copy at dst (e.g. re-install while the scheduled scan
// runs) doesn't block the update and a failed copy never leaves half a file.
func copyFileAtomic(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	// Remove first: O_TRUNC would reuse an existing file — and its owner
	// and permissions — rather than create ours.
	os.Remove(tmp)
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if runtime.GOOS == "windows" {
		os.Remove(dst) // rename-over is not atomic on Windows
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// installGUI installs the double-click launcher: a single executable on
// Windows and Linux, an .app bundle (a directory) on macOS.
func installGUI(src, dst string) error {
	if same, _ := sameFilePath(src, dst); same {
		return nil
	}
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return copyFileAtomic(src, dst)
	}
	if err := os.RemoveAll(dst); err != nil {
		return err
	}
	if err := copyTree(src, dst); err != nil {
		return err
	}
	if runtime.GOOS == "darwin" {
		execCmd("xattr", "-dr", "com.apple.quarantine", dst)
	}
	return nil
}

// copyTree copies a directory of regular files (an .app bundle), keeping
// each file's permission bits. Anything else in the tree is skipped.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode().Perm()|0o644)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, in)
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		return err
	})
}

func sameFilePath(a, b string) (bool, error) {
	fa, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	fb, err := os.Stat(b)
	if err != nil {
		return false, err
	}
	return os.SameFile(fa, fb), nil
}

// writeManifest writes the starter scan manifest (BOM-less UTF-8). ocr is
// enabled only when the tools were confirmed present.
func writeManifest(p installPaths, ocr bool) error {
	paths, excludes := `"/home", "/srv"`, `"*.iso"`
	switch runtime.GOOS {
	case "windows":
		paths, excludes = `"C:\\Users"`, `"*.iso"`
	case "darwin":
		paths, excludes = `"/Users"`, `"*.app", "*.iso"`
	}
	manifest := fmt.Sprintf(`{
  "paths": [%s],
  "excludes": [%s],
  "min_confidence": "medium",
  "syslog_out": %q,
  "syslog_format": "json",
  "ocr": %v,
  "quiet": true
}
`, paths, excludes, p.logPath, ocr)
	// Round-trip through the manifest parser so the installer can never
	// ship a manifest the scanner rejects.
	tmp := p.manifest + ".new"
	os.Remove(tmp)
	if err := os.WriteFile(tmp, []byte(manifest), 0o644); err != nil {
		return err
	}
	if _, err := loadConfig(tmp); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("generated manifest failed validation: %w", err)
	}
	return os.Rename(tmp, p.manifest)
}

// installOCRTools tries the platform's package manager for tesseract and
// poppler and reports whether OCR is usable afterwards. Failures are
// explained, never fatal: the scan works without OCR.
func installOCRTools() bool {
	if img, pdf := extract.HaveOCR(); img && pdf {
		okf("already installed (tesseract + pdftoppm)")
		return true
	}
	notef("installing Tesseract and poppler — this can take a few minutes…")
	switch runtime.GOOS {
	case "windows":
		// Refresh the community source first, and pin every query to it:
		// letting winget consult the msstore source fails with 0x8a15000f
		// ("view the following agreements", region required) on machines
		// where the Store was never initialized — common on servers and
		// fresh fleet images.
		tryRun("winget", "source", "update", "--name", "winget", "--disable-interactivity")
		wingetInstall := func(id string) bool {
			return tryRun("winget", "install", "-e", "--id", id,
				"--source", "winget", "--silent", "--disable-interactivity",
				"--accept-package-agreements", "--accept-source-agreements")
		}
		// Three rungs per tool: winget → chocolatey → direct download of
		// the pinned official release (SHA-256 verified), so a machine with
		// broken package managers still ends up with working OCR.
		if !wingetInstall("UB-Mannheim.TesseractOCR") && !tryRun("choco", "install", "tesseract", "-y") {
			installTesseractDirect()
		}
		if !wingetInstall("oschwartz10612.Poppler") && !tryRun("choco", "install", "poppler", "-y") {
			installPopplerDirect()
		}
	case "darwin":
		// Homebrew refuses to run as root; run it as the invoking user.
		user := os.Getenv("SUDO_USER")
		if user == "" || !tryRun("sudo", "-u", user, "brew", "install", "tesseract", "poppler") {
			notef("could not run Homebrew; install manually with: brew install tesseract poppler")
		}
	default:
		switch {
		case haveCmd("apt-get"):
			tryRun("apt-get", "install", "-y", "tesseract-ocr", "poppler-utils")
		case haveCmd("dnf"):
			tryRun("dnf", "install", "-y", "tesseract", "poppler-utils")
		case haveCmd("yum"):
			tryRun("yum", "install", "-y", "tesseract", "poppler-utils")
		default:
			notef("no known package manager found; install tesseract and poppler manually")
		}
	}
	extract.RefreshOCRTools() // drop lookups cached before the installs
	img, pdf := extract.HaveOCR()
	switch {
	case img && pdf:
		okf("ready (images and scanned PDFs)")
	case img:
		warnf("Tesseract is ready but pdftoppm is missing — images will be read, scanned PDFs will only be flagged")
	default:
		warnf("OCR tools could not be installed — scans still work; scanned documents are listed as needing OCR")
		if runtime.GOOS == "windows" {
			notef("to add OCR manually:")
			notef("  1. Tesseract: run the installer from https://github.com/UB-Mannheim/tesseract/wiki")
			notef("     (the standard install path is auto-detected afterwards)")
			notef(`  2. Poppler:  unzip a release from https://github.com/oschwartz10612/poppler-windows/releases`)
			notef(`     into C:\Program Files\poppler (auto-detected), or set PRIVACYLENS_PDFTOPPM to pdftoppm.exe`)
			notef(`  3. Enable OCR: set "ocr": true in the scan manifest`)
		}
	}
	return img && pdf
}

// Pinned official OCR-tool releases for the direct-download fallback, used
// only when winget and chocolatey both fail (e.g. winget's 0x8a15000f
// broken-source state). Every download is verified against its SHA-256
// before use; a mismatch aborts that tool's install. Bump URL + hash
// together when updating.
const (
	tesseractSetupURL = "https://github.com/UB-Mannheim/tesseract/releases/download/v5.4.0.20240606/tesseract-ocr-w64-setup-5.4.0.20240606.exe"
	tesseractSetupSHA = "c885fff6998e0608ba4bb8ab51436e1c6775c2bafc2559a19b423e18678b60c9"
	popplerZipURL     = "https://github.com/oschwartz10612/poppler-windows/releases/download/v26.02.0-0/Release-26.02.0-0.zip"
	popplerZipSHA     = "993e4a94376ed712fafc7058d724ea0b943d118bbd2305cd9ed55174eb85cda5"
)

// installTesseractDirect downloads the official UB-Mannheim installer and
// runs it silently (NSIS /S). Installs to the standard Program Files
// location, which the scanner auto-detects.
func installTesseractDirect() bool {
	notef("package managers unavailable — downloading the official Tesseract installer (48 MB)…")
	tmp := filepath.Join(os.TempDir(), "privacylens-tesseract-setup.exe")
	if err := downloadVerified(tesseractSetupURL, tesseractSetupSHA, tmp); err != nil {
		warnf("Tesseract download failed: %v", err)
		return false
	}
	defer os.Remove(tmp)
	notef("running the Tesseract installer (silent)…")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := exec.CommandContext(ctx, tmp, "/S").Run(); err != nil {
		warnf("Tesseract installer failed: %v", err)
		return false
	}
	return true
}

// installPopplerDirect downloads the official poppler-windows release zip
// and unpacks it under Program Files\poppler, where the scanner auto-detects
// pdftoppm (zip releases are not installers and never end up on PATH).
func installPopplerDirect() bool {
	notef("package managers unavailable — downloading the official poppler release (16 MB)…")
	tmp := filepath.Join(os.TempDir(), "privacylens-poppler.zip")
	if err := downloadVerified(popplerZipURL, popplerZipSHA, tmp); err != nil {
		warnf("poppler download failed: %v", err)
		return false
	}
	defer os.Remove(tmp)
	base := os.Getenv("ProgramFiles")
	if base == "" {
		base = `C:\Program Files`
	}
	dest := filepath.Join(base, "poppler")
	if err := extractZip(tmp, dest); err != nil {
		warnf("poppler unpack failed: %v", err)
		return false
	}
	return true
}

// downloadVerified fetches url to dst and verifies its SHA-256; on mismatch
// the file is deleted and an error returned. Honors HTTP(S)_PROXY.
func downloadVerified(url, wantSHA, dst string) error {
	client := &http.Client{Timeout: 15 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: %s", resp.Status)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(dst)
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantSHA {
		os.Remove(dst)
		return fmt.Errorf("checksum mismatch (got %s, want %s) — refusing to use the download", got, wantSHA)
	}
	return nil
}

// extractZip unpacks zipPath under destDir, refusing entries that would
// escape it (zip-slip).
func extractZip(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		rel := filepath.Clean(filepath.FromSlash(f.Name))
		if rel == "." || filepath.IsAbs(rel) || strings.HasPrefix(rel, "..") {
			continue
		}
		dst := filepath.Join(destDir, rel)
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, rc)
		rc.Close()
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// registerSchedule sets up the weekly scan for the current platform.
func registerSchedule(p installPaths) error {
	switch runtime.GOOS {
	case "windows":
		// Machine-wide data dir so the weekly SYSTEM scan's saved reports
		// land somewhere findable (not SYSTEM's hidden profile) and manual
		// runs share it.
		if err := execCmd("setx", "/M", "PRIVACYLENS_DATA_DIR", p.etcDir); err != nil {
			return fmt.Errorf("setting PRIVACYLENS_DATA_DIR: %w", err)
		}
		tr := fmt.Sprintf(`"%s" -config "%s"`, p.binPath, p.manifest)
		if err := execCmd("schtasks", "/Create", "/TN", taskName, "/TR", tr,
			"/SC", "WEEKLY", "/D", "SUN", "/ST", "02:00",
			"/RU", "SYSTEM", "/RL", "HIGHEST", "/F"); err != nil {
			return fmt.Errorf("schtasks: %w", err)
		}
		return nil
	case "darwin":
		if err := os.WriteFile(launchdPlistPath, []byte(launchdPlist), 0o644); err != nil {
			return err
		}
		execCmd("launchctl", "bootout", "system", launchdPlistPath) // reload cleanly if present
		return execCmd("launchctl", "bootstrap", "system", launchdPlistPath)
	default:
		if !haveCmd("systemctl") {
			return fmt.Errorf("systemd not found; schedule the scan manually (cron): privacylens -config %s", p.manifest)
		}
		if err := os.WriteFile(systemdServicePath, []byte(systemdService), 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(systemdTimerPath, []byte(systemdTimer), 0o644); err != nil {
			return err
		}
		if err := execCmd("systemctl", "daemon-reload"); err != nil {
			return err
		}
		return execCmd("systemctl", "enable", "--now", "privacylens.timer")
	}
}

// removeSchedule unregisters the weekly scan; gone reports each removal.
func removeSchedule(gone func(what string, err error)) {
	switch runtime.GOOS {
	case "windows":
		if execCmd("schtasks", "/Query", "/TN", taskName) == nil {
			gone(`Task Scheduler task "`+taskName+`"`, execCmd("schtasks", "/Delete", "/TN", taskName, "/F"))
		}
		execCmd("reg", "delete", envRegKey, "/v", "PRIVACYLENS_DATA_DIR", "/f")
	case "darwin":
		execCmd("launchctl", "bootout", "system", launchdPlistPath)
		gone("launchd job "+launchdLabel, os.Remove(launchdPlistPath))
	default:
		execCmd("systemctl", "disable", "--now", "privacylens.timer")
		gone("systemd timer", os.Remove(systemdTimerPath))
		gone("systemd service", os.Remove(systemdServicePath))
		execCmd("systemctl", "daemon-reload")
	}
}

func haveCmd(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// run executes a command, surfacing its combined output only on failure.
func execCmd(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("%s: %s", err, msg)
		}
		return err
	}
	return nil
}

// tryRun is run for optional steps: prints the failure and carries on.
func tryRun(name string, args ...string) bool {
	if !haveCmd(name) {
		return false
	}
	if err := execCmd(name, args...); err != nil {
		notef("%s did not work (%v); trying the next option", name, err)
		return false
	}
	return true
}

const desktopEntry = `[Desktop Entry]
Type=Application
Name=PrivacyLens
Comment=Find personal data (PII) stored on this computer
Exec=/usr/local/bin/privacylens-gui
Terminal=false
Categories=Utility;Security;
`

const systemdService = `# Installed by "privacylens install".
[Unit]
Description=PrivacyLens PII scan
Wants=privacylens.timer

[Service]
Type=oneshot
ExecStart=/usr/local/bin/privacylens -config /etc/privacylens/scan.json
# Exit code 1 means "PII found" — a successful scan, not a failure.
SuccessExitStatus=1
Nice=10
IOSchedulingClass=idle

[Install]
WantedBy=multi-user.target
`

const systemdTimer = `# Installed by "privacylens install".
[Unit]
Description=Weekly PrivacyLens PII scan

[Timer]
OnCalendar=Sun 02:00
Persistent=true
RandomizedDelaySec=15m

[Install]
WantedBy=timers.target
`

const launchdPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!-- Installed by "privacylens install". Weekly scan, Sundays 02:00. -->
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.cybx.privacylens</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/privacylens</string>
    <string>-config</string>
    <string>/etc/privacylens/scan.json</string>
  </array>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Weekday</key>
    <integer>0</integer>
    <key>Hour</key>
    <integer>2</integer>
    <key>Minute</key>
    <integer>0</integer>
  </dict>
  <key>StandardErrorPath</key>
  <string>/var/log/privacylens/stderr.log</string>
  <key>ProcessType</key>
  <string>Background</string>
  <key>LowPriorityIO</key>
  <true/>
</dict>
</plist>
`
