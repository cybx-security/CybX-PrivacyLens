package main

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
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

// The `privacylens install` subcommand: one installer for every platform,
// replacing the per-OS shell/PowerShell scripts. Run elevated/as root, it
//   - copies the binary to the standard location
//   - writes a starter scan manifest (kept if one already exists)
//   - registers the weekly scheduled scan (Task Scheduler / systemd /
//     launchd), Sundays 02:00
//   - installs the OCR tools (tesseract + poppler) via the platform's
//     package manager when one is available, and enables "ocr": true in a
//     freshly written manifest when they're usable
// `privacylens uninstall` removes the schedule (files and logs are left in
// place, like the old scripts did).

// installPaths resolves the per-OS install layout.
type installPaths struct {
	binDir   string // where the binary lands
	binPath  string
	etcDir   string // manifest directory
	manifest string
	logDir   string // findings log directory the SIEM agent tails
	logPath  string
}

func resolveInstallPaths() installPaths {
	var p installPaths
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		dir := filepath.Join(base, "PrivacyLens")
		p.binDir, p.etcDir = dir, dir
		p.binPath = filepath.Join(dir, "privacylens.exe")
		p.manifest = filepath.Join(dir, "scan.json")
		p.logPath = paths.SystemFindingsLog()
		p.logDir = filepath.Dir(p.logPath)
		return p
	}
	p.binDir = "/usr/local/bin"
	p.binPath = "/usr/local/bin/privacylens"
	p.etcDir = "/etc/privacylens"
	p.manifest = "/etc/privacylens/scan.json"
	p.logPath = paths.SystemFindingsLog()
	p.logDir = filepath.Dir(p.logPath)
	return p
}

func runInstall(args []string) int {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	noOCR := fs.Bool("no-ocr", false, "skip installing the OCR tools (tesseract, poppler)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage:
  privacylens install [-no-ocr]

Installs PrivacyLens system-wide (run as root / from an elevated prompt):
binary, starter scan manifest, weekly scheduled scan (Sundays 02:00), and —
unless -no-ocr is given — the OCR tools via the system package manager.
Existing manifests are never overwritten.

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "error: install must run as root (sudo privacylens install)")
		return exitError
	}

	p := resolveInstallPaths()
	for _, dir := range []string{p.binDir, p.etcDir, p.logDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot create %s: %v (run from an elevated prompt?)\n", dir, err)
			return exitError
		}
	}

	// Every scan — GUI or CLI, elevated or not — appends to the findings
	// log in this directory by default, so non-admin users need append
	// rights or their scans silently miss the SIEM. S-1-5-32-545 is the
	// BUILTIN\Users well-known SID (language-independent). Grant only append,
	// read-attributes, and synchronization rights inherited by the log file;
	// broad Modify rights would let any user delete or rewrite SIEM evidence.
	// Failure is a warning, not fatal:
	// elevated/scheduled scans still work without it.
	if runtime.GOOS == "windows" {
		if err := execCmd("icacls", p.logDir, "/grant", "*S-1-5-32-545:(OI)(CI)(AD,RA,REA,WEA,WA,S)"); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not grant Users write access to %s (%v); non-elevated scans will fall back to per-user logs\n", p.logDir, err)
		} else {
			fmt.Printf("Granted Users write access: %s\n", p.logDir)
		}
	}

	if err := installBinary(p.binPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: installing binary: %v\n", err)
		return exitError
	}
	fmt.Printf("Installed binary: %s\n", p.binPath)

	// OCR tools before the manifest, so a fresh manifest can enable OCR
	// only when the tools actually work.
	ocrReady := false
	if *noOCR {
		fmt.Println("OCR tools: skipped (-no-ocr)")
	} else {
		ocrReady = installOCRTools()
	}

	if _, err := os.Stat(p.manifest); os.IsNotExist(err) {
		if err := writeManifest(p, ocrReady); err != nil {
			fmt.Fprintf(os.Stderr, "error: writing manifest: %v\n", err)
			return exitError
		}
		fmt.Printf("Wrote starter manifest: %s (edit paths for this machine)\n", p.manifest)
	} else {
		fmt.Printf("Kept existing manifest: %s\n", p.manifest)
		if ocrReady {
			fmt.Println(`  OCR tools are ready — set "ocr": true in the manifest to read scanned documents`)
		}
	}

	if err := registerSchedule(p); err != nil {
		fmt.Fprintf(os.Stderr, "error: registering weekly scan: %v\n", err)
		return exitError
	}

	fmt.Printf("Findings log for the Insights agent: %s\n", p.logPath)
	switch runtime.GOOS {
	case "windows":
		fmt.Println(`Weekly scan registered: Task Scheduler "PrivacyLens Scan", Sundays 02:00, as SYSTEM.`)
		fmt.Println(`On-demand scan:  Start-ScheduledTask -TaskName "PrivacyLens Scan"`)
	case "darwin":
		fmt.Println("Weekly scan registered: launchd com.cybx.privacylens, Sundays 02:00.")
		fmt.Println("On-demand scan:  sudo launchctl start com.cybx.privacylens")
	default:
		fmt.Println("Weekly scan registered: systemd privacylens.timer, Sundays 02:00.")
		fmt.Println("On-demand scan:  systemctl start privacylens.service")
	}
	return exitClean
}

func runUninstall() int {
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "error: uninstall must run as root (sudo privacylens uninstall)")
		return exitError
	}
	switch runtime.GOOS {
	case "windows":
		execCmd("schtasks", "/Delete", "/TN", "PrivacyLens Scan", "/F")
		execCmd("reg", "delete", `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`,
			"/v", "PRIVACYLENS_DATA_DIR", "/f")
	case "darwin":
		execCmd("launchctl", "bootout", "system", "/Library/LaunchDaemons/com.cybx.privacylens.plist")
		os.Remove("/Library/LaunchDaemons/com.cybx.privacylens.plist")
	default:
		execCmd("systemctl", "disable", "--now", "privacylens.timer")
		os.Remove("/etc/systemd/system/privacylens.timer")
		os.Remove("/etc/systemd/system/privacylens.service")
		execCmd("systemctl", "daemon-reload")
	}
	fmt.Println("Removed the scheduled scan. Binary, manifest, and logs were left in place.")
	return exitClean
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
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	// Write to a temp name then rename, so a running copy at dst (e.g.
	// re-install while the scheduled scan runs) doesn't block the update.
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
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
		return err
	}
	if runtime.GOOS == "darwin" {
		// A downloaded binary may carry the quarantine flag, which blocks
		// launchd from running it.
		execCmd("xattr", "-d", "com.apple.quarantine", dst)
	}
	return nil
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
		fmt.Println("OCR tools: already present (tesseract + pdftoppm)")
		return true
	}
	fmt.Println("OCR tools: installing tesseract + poppler…")
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
			fmt.Println("  could not run Homebrew; install manually with: brew install tesseract poppler")
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
			fmt.Println("  no known package manager found; install tesseract and poppler manually")
		}
	}
	extract.RefreshOCRTools() // drop lookups cached before the installs
	img, pdf := extract.HaveOCR()
	switch {
	case img && pdf:
		fmt.Println("OCR tools: ready (images + scanned PDFs)")
	case img:
		fmt.Println("OCR tools: tesseract ready, pdftoppm missing — images will OCR, scanned PDFs will only be flagged")
	default:
		fmt.Println("OCR tools: not available — scans still work; scanned documents are flagged as needing OCR")
		if runtime.GOOS == "windows" {
			fmt.Println("  To add OCR manually:")
			fmt.Println("    1. Tesseract: run the installer from https://github.com/UB-Mannheim/tesseract/wiki")
			fmt.Println("       (the standard install path is auto-detected afterwards)")
			fmt.Println(`    2. Poppler:  unzip a release from https://github.com/oschwartz10612/poppler-windows/releases`)
			fmt.Println(`       into C:\Program Files\poppler (auto-detected), or set PRIVACYLENS_PDFTOPPM to pdftoppm.exe`)
			fmt.Println(`    3. Enable OCR: set "ocr": true in the scan manifest`)
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
	fmt.Println("  package managers unavailable — downloading the official Tesseract installer (48 MB)…")
	tmp := filepath.Join(os.TempDir(), "privacylens-tesseract-setup.exe")
	if err := downloadVerified(tesseractSetupURL, tesseractSetupSHA, tmp); err != nil {
		fmt.Printf("  tesseract download failed: %v\n", err)
		return false
	}
	defer os.Remove(tmp)
	fmt.Println("  running Tesseract installer (silent)…")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := exec.CommandContext(ctx, tmp, "/S").Run(); err != nil {
		fmt.Printf("  tesseract installer failed: %v\n", err)
		return false
	}
	return true
}

// installPopplerDirect downloads the official poppler-windows release zip
// and unpacks it under Program Files\poppler, where the scanner auto-detects
// pdftoppm (zip releases are not installers and never end up on PATH).
func installPopplerDirect() bool {
	fmt.Println("  package managers unavailable — downloading the official poppler release (16 MB)…")
	tmp := filepath.Join(os.TempDir(), "privacylens-poppler.zip")
	if err := downloadVerified(popplerZipURL, popplerZipSHA, tmp); err != nil {
		fmt.Printf("  poppler download failed: %v\n", err)
		return false
	}
	defer os.Remove(tmp)
	base := os.Getenv("ProgramFiles")
	if base == "" {
		base = `C:\Program Files`
	}
	dest := filepath.Join(base, "poppler")
	if err := extractZip(tmp, dest); err != nil {
		fmt.Printf("  poppler unpack failed: %v\n", err)
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
		// Machine-wide data dir so flagless/GUI runs write the same
		// findings log the Wazuh agent tails.
		if err := execCmd("setx", "/M", "PRIVACYLENS_DATA_DIR", p.etcDir); err != nil {
			return fmt.Errorf("setting PRIVACYLENS_DATA_DIR: %w", err)
		}
		tr := fmt.Sprintf(`"%s" -config "%s"`, p.binPath, p.manifest)
		if err := execCmd("schtasks", "/Create", "/TN", "PrivacyLens Scan", "/TR", tr,
			"/SC", "WEEKLY", "/D", "SUN", "/ST", "02:00",
			"/RU", "SYSTEM", "/RL", "HIGHEST", "/F"); err != nil {
			return fmt.Errorf("schtasks: %w", err)
		}
		return nil
	case "darwin":
		const plistPath = "/Library/LaunchDaemons/com.cybx.privacylens.plist"
		if err := os.WriteFile(plistPath, []byte(launchdPlist), 0o644); err != nil {
			return err
		}
		execCmd("launchctl", "bootout", "system", plistPath) // reload cleanly if present
		return execCmd("launchctl", "bootstrap", "system", plistPath)
	default:
		if !haveCmd("systemctl") {
			return fmt.Errorf("systemd not found; schedule the scan manually (cron): privacylens -config %s", p.manifest)
		}
		if err := os.WriteFile("/etc/systemd/system/privacylens.service", []byte(systemdService), 0o644); err != nil {
			return err
		}
		if err := os.WriteFile("/etc/systemd/system/privacylens.timer", []byte(systemdTimer), 0o644); err != nil {
			return err
		}
		if err := execCmd("systemctl", "daemon-reload"); err != nil {
			return err
		}
		return execCmd("systemctl", "enable", "--now", "privacylens.timer")
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
		fmt.Printf("  %s failed: %v\n", name, err)
		return false
	}
	return true
}

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
