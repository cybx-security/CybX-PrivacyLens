// Package update checks GitHub Releases for a newer PrivacyLens, downloads
// the installer for this platform, verifies it against the release's
// SHA256SUMS.txt, and runs it. Releases are unsigned for now: integrity
// rests on HTTPS to GitHub plus the published checksums, so anything that
// can publish a release to the configured repository can update every
// customer machine — guard that account accordingly.
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// APIBase is the GitHub API root; a variable so tests (and a staging
// feed, via PRIVACYLENS_UPDATE_API) can point it elsewhere.
var APIBase = "https://api.github.com"

func init() {
	if v := os.Getenv("PRIVACYLENS_UPDATE_API"); v != "" {
		APIBase = strings.TrimRight(v, "/")
	}
}

// SumsFile is the checksum list every release must carry. The release
// workflow (.github/workflows/release.yml) names it SHA256SUMS and
// scripts/release.sh SHA256SUMS.txt; both are accepted.
const SumsFile = "SHA256SUMS.txt"

func isSumsFile(name string) bool { return name == SumsFile || name == "SHA256SUMS" }

// Release is the newest published release and the installer in it for
// this platform.
type Release struct {
	Version     string    `json:"version"` // "0.9.11", no leading v
	Tag         string    `json:"tag"`
	Notes       string    `json:"notes"`
	URL         string    `json:"url"` // release page
	PublishedAt time.Time `json:"published_at"`
	Asset       Asset     `json:"asset"`
	SumsURL     string    `json:"-"`
}

// Asset is one downloadable file of a release.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Size int64  `json:"size"`
}

// ErrNoAsset means the release has no installer for this OS/architecture.
var ErrNoAsset = errors.New("release has no installer for this platform")

var client = &http.Client{Timeout: 10 * time.Minute}

// Check fetches the latest release of repo and reports whether it is newer
// than current. A release that is not newer is still returned, so callers
// can say "you have the latest".
func Check(ctx context.Context, repo, current string) (rel *Release, newer bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, APIBase+"/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "PrivacyLens/"+current)
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("cannot reach GitHub: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, fmt.Errorf("no releases found at github.com/%s (is the repository public, with at least one release?)", repo)
	}
	if resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0" {
		// Anonymous API calls are limited per source IP (60/hour); an
		// office full of machines behind one NAT can hit it.
		wait := "a little while"
		if reset, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
			if d := time.Until(time.Unix(reset, 0)).Round(time.Minute); d > 0 {
				wait = fmt.Sprintf("about %d minute(s)", int(d.Minutes())+1)
			}
		}
		return nil, false, fmt.Errorf("GitHub is limiting update checks from this network right now; try again in %s", wait)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("GitHub answered %s", resp.Status)
	}
	var gh struct {
		TagName     string    `json:"tag_name"`
		Body        string    `json:"body"`
		HTMLURL     string    `json:"html_url"`
		PublishedAt time.Time `json:"published_at"`
		Assets      []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
			Size int64  `json:"size"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&gh); err != nil {
		return nil, false, fmt.Errorf("reading release: %w", err)
	}
	rel = &Release{
		Version: strings.TrimPrefix(gh.TagName, "v"), Tag: gh.TagName,
		Notes: gh.Body, URL: gh.HTMLURL, PublishedAt: gh.PublishedAt,
	}
	want := AssetName(runtime.GOOS, runtime.GOARCH, rel.Version)
	for _, a := range gh.Assets {
		switch {
		case a.Name == want:
			rel.Asset = Asset{a.Name, a.URL, a.Size}
		case isSumsFile(a.Name):
			rel.SumsURL = a.URL
		}
	}
	newer = CompareVersions(rel.Version, current) > 0
	if newer && rel.Asset.Name == "" {
		return rel, true, ErrNoAsset
	}
	return rel, newer, nil
}

// AssetName is the installer file name build-all.sh produces for a
// platform, which is what the release must carry.
func AssetName(goos, goarch, version string) string {
	switch goos {
	case "darwin":
		return "PrivacyLens-" + version + ".pkg" // universal
	case "windows":
		return "PrivacyLens-Setup-" + version + ".exe" // x64 + ARM64
	default:
		arch := goarch
		if arch == "arm" {
			arch = "armv7"
		}
		return "PrivacyLens-" + version + "-" + goos + "-" + arch + ".tar.gz"
	}
}

var versionRE = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)`)

// CompareVersions orders "X.Y.Z" strings numerically (a leading v is
// ignored): -1, 0, or 1. Anything unparsable sorts lowest, so a dev build
// is always "older" than a real release.
func CompareVersions(a, b string) int {
	pa, pb := parseVersion(a), parseVersion(b)
	for i := range pa {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func parseVersion(v string) [3]int {
	var out [3]int
	m := versionRE.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return [3]int{-1, -1, -1}
	}
	for i := 0; i < 3; i++ {
		out[i], _ = strconv.Atoi(m[i+1])
	}
	return out
}

// Download fetches the release's installer into dir and verifies it
// against the release's SHA256SUMS.txt. progress, if set, is called with
// bytes received so far and the total. The returned path is the verified
// installer; on any failure the partial file is removed.
func Download(ctx context.Context, rel *Release, dir string, progress func(done, total int64)) (string, error) {
	if rel.Asset.URL == "" {
		return "", ErrNoAsset
	}
	if rel.SumsURL == "" {
		return "", fmt.Errorf("release %s has no %s, so the download cannot be verified; refusing to install it", rel.Tag, SumsFile)
	}
	want, err := expectedSum(ctx, rel)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, rel.Asset.Name)
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	resp, err := get(ctx, rel.Asset.URL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	h := sha256.New()
	var done int64
	buf := make([]byte, 256<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				return "", werr
			}
			h.Write(buf[:n])
			done += int64(n)
			if progress != nil {
				progress(done, rel.Asset.Size)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", fmt.Errorf("download interrupted: %w", rerr)
		}
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return "", fmt.Errorf("downloaded %s does not match the release's checksum (got %s, want %s); not installing it", rel.Asset.Name, got[:12], want[:12])
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	ok = true
	return path, nil
}

// expectedSum reads the asset's checksum out of the release's SHA256SUMS.txt
// (sha256sum/shasum format: "<hex>  <name>").
func expectedSum(ctx context.Context, rel *Release) (string, error) {
	resp, err := get(ctx, rel.SumsURL)
	if err != nil {
		return "", fmt.Errorf("fetching %s: %w", SumsFile, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if filepath.Base(name) == rel.Asset.Name && len(fields[0]) == 64 {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("%s in release %s has no entry for %s", SumsFile, rel.Tag, rel.Asset.Name)
}

func get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "PrivacyLens-updater")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return resp, nil
}

// ErrManual means the platform has no silent installer; the caller shows
// the downloaded file and the commands to finish by hand.
var ErrManual = errors.New("manual install")

// ManualSteps are the commands that finish an update on a platform with no
// silent installer (Linux): unpack the archive and run its install script.
func ManualSteps(installer string) string {
	dir := strings.TrimSuffix(filepath.Base(installer), ".tar.gz")
	return fmt.Sprintf("cd %s && tar -xzf %s && sudo ./%s/install.sh", filepath.Dir(installer), filepath.Base(installer), dir)
}

// Install runs the downloaded installer for this platform.
//
//   - macOS: the universal .pkg through /usr/sbin/installer. Running as a
//     normal user (the GUI launcher), macOS's own administrator-password
//     dialog is shown first; as root it just runs. The package replaces
//     the program and the app and re-runs "privacylens install".
//   - Windows: the setup wizard silently (/S). From a normal user it is
//     started elevated, so Windows asks for permission (UAC); the wizard
//     then closes any running PrivacyLens window launcher (which may be
//     the caller!) and, with relaunch, reopens it as the signed-in user
//     when it is done. From an elevated prompt it runs and waits.
//   - Linux: ErrManual; see ManualSteps.
func Install(ctx context.Context, installer string, relaunch bool) error {
	switch runtime.GOOS {
	case "darwin":
		return installPkg(ctx, installer)
	case "windows":
		return installSetup(ctx, installer, relaunch)
	default:
		return ErrManual
	}
}

func installPkg(ctx context.Context, pkg string) error {
	if strings.ContainsAny(pkg, "'\"\\") {
		return fmt.Errorf("installer path %q has characters that cannot be quoted safely", pkg)
	}
	var cmd *exec.Cmd
	if os.Geteuid() == 0 {
		cmd = exec.CommandContext(ctx, "/usr/sbin/installer", "-pkg", pkg, "-target", "/")
	} else {
		script := fmt.Sprintf(`do shell script "/usr/sbin/installer -pkg '%s' -target /" with administrator privileges with prompt "PrivacyLens needs your password to install the update."`, pkg)
		cmd = exec.CommandContext(ctx, "/usr/bin/osascript", "-e", script)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "User canceled") || strings.Contains(msg, "-128") {
			return errors.New("the update was cancelled at the password prompt")
		}
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("installer failed: %s", oneLine(msg))
	}
	return nil
}

func installSetup(ctx context.Context, setup string, relaunch bool) error {
	args := "/S"
	if relaunch {
		args += " /RELAUNCH"
	}
	if isElevated() {
		cmd := exec.CommandContext(ctx, setup, strings.Fields(args)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("setup failed: %s", oneLine(strings.TrimSpace(string(out)+" "+err.Error())))
		}
		return nil
	}
	// Start-Process -Verb RunAs is the supported way to trigger UAC from a
	// non-elevated process. Not -Wait: the wizard terminates this process
	// (StopApp) before it finishes, and must outlive it.
	ps := fmt.Sprintf(`Start-Process -FilePath '%s' -ArgumentList '%s' -Verb RunAs`, strings.ReplaceAll(setup, "'", "''"), args)
	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", ps).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "canceled by the user") {
			return errors.New("the update was cancelled at the Windows permission prompt")
		}
		return fmt.Errorf("could not start setup: %s", oneLine(msg+" "+err.Error()))
	}
	return nil
}

// isElevated reports whether a Windows process holds administrator rights,
// by the cheapest reliable probe: only elevated processes may open the
// physical drive.
func isElevated() bool {
	f, err := os.Open(`\\.\PHYSICALDRIVE0`)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// Relaunch starts the freshly installed GUI launcher on macOS (the Windows
// wizard relaunches by itself). It reports whether it did: a server
// started from a terminal rather than the app is not relaunched.
func Relaunch() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	app := AppBundle()
	if app == "" {
		return false
	}
	// -n: a new instance even though this one is still running.
	return exec.Command("open", "-n", app).Start() == nil
}

// AppBundle returns the .app bundle this process runs from, or "".
func AppBundle() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if i := strings.Index(exe, ".app/Contents/MacOS/"); i >= 0 {
		return exe[:i+len(".app")]
	}
	return ""
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// Elevated reports whether this process may install system-wide: root on
// Unix, an administrator token on Windows.
func Elevated() bool {
	if runtime.GOOS == "windows" {
		return isElevated()
	}
	return os.Geteuid() == 0
}
