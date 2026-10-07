package gui

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/rdataback/privacylens/internal/scanner"
)

// mailAccess tells the page whether a mail scan will be able to read the
// Outlook mailbox on this computer, and if not, what the customer has to
// switch on. macOS protects Outlook for Mac's data folder: reads fail
// until the reading app has Full Disk Access, which no API can prompt
// for — the user has to flip the switch in System Settings. The best the
// GUI can do is notice, open the right settings pane for them, and name
// the exact app to turn on.
type mailAccess struct {
	OS       string `json:"os"`
	Present  bool   `json:"present"`            // Outlook data folder exists here
	Readable bool   `json:"readable"`           // and this process may read it
	Location string `json:"location,omitempty"` // the folder in question
	// NeedsFullDiskAccess is set on macOS when the folder exists but
	// reading it is refused.
	NeedsFullDiskAccess bool `json:"needs_full_disk_access"`
	// GrantTo names the app to switch on in Full Disk Access: PrivacyLens
	// itself when running from the .app bundle, otherwise the terminal
	// app the server was started from (macOS attributes a terminal
	// command's file access to the terminal).
	GrantTo string `json:"grant_to,omitempty"`
	AppPath string `json:"app_path,omitempty"` // the .app bundle to add, when GrantTo is PrivacyLens
	// StrayCopy is set when this window runs from a bundle other than the
	// installed one: Full Disk Access is granted per bundle, so the grant
	// must go to the installed copy and that copy must be the one opened.
	StrayCopy string `json:"stray_copy,omitempty"`
}

// outlookLocations and openDiskAccessSettings are indirections so tests
// can point the check at a fixture and keep System Settings closed.
var (
	outlookLocations       = scanner.OutlookDataLocations
	openDiskAccessSettings = func(reveal string) error {
		if reveal != "" {
			// Reveal the bundle in Finder so it can be dragged onto the
			// Full Disk Access list — the "+" picker is easy to get lost in.
			return exec.Command("open", "-R", reveal).Start()
		}
		return exec.Command("open", "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles").Start()
	}
)

func checkMailAccess() mailAccess {
	ma := mailAccess{OS: runtime.GOOS}
	for _, loc := range outlookLocations() {
		if _, err := os.Stat(loc); err != nil && !errors.Is(err, fs.ErrPermission) {
			continue
		}
		ma.Present = true
		ma.Location = loc
		_, err := os.ReadDir(loc)
		ma.Readable = err == nil
		if err == nil {
			break // one readable location is proof enough
		}
		if runtime.GOOS == "darwin" && errors.Is(err, fs.ErrPermission) {
			ma.NeedsFullDiskAccess = true
			ma.GrantTo, ma.AppPath = grantTarget()
			if running, installed := strayCopy(); running != "" {
				ma.StrayCopy, ma.AppPath = running, installed
			}
			break
		}
	}
	return ma
}

// grantTarget names what to switch on in Full Disk Access and, when it is
// the app bundle, where that bundle is.
func grantTarget() (name, appPath string) {
	exe, err := os.Executable()
	if err == nil {
		if i := strings.Index(exe, ".app/Contents/MacOS/"); i >= 0 {
			return "PrivacyLens", exe[:i+len(".app")]
		}
	}
	switch os.Getenv("TERM_PROGRAM") {
	case "Apple_Terminal":
		return "Terminal", ""
	case "iTerm.app":
		return "iTerm", ""
	case "vscode":
		return "Visual Studio Code", ""
	case "WarpTerminal":
		return "Warp", ""
	case "ghostty":
		return "Ghostty", ""
	}
	return "the terminal app you started PrivacyLens from", ""
}

func (s *server) handleMailAccess(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(checkMailAccess())
}

// handleOpenDiskAccess opens System Settings on the Full Disk Access pane
// (POST), or with ?reveal=1 shows the PrivacyLens.app bundle in Finder.
// macOS only; there is nothing equivalent to open elsewhere.
func (s *server) handleOpenDiskAccess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if runtime.GOOS != "darwin" {
		http.Error(w, "Full Disk Access is a macOS setting", http.StatusNotFound)
		return
	}
	reveal := ""
	if r.URL.Query().Get("reveal") == "1" {
		if _, app := grantTarget(); app != "" {
			reveal = filepath.Clean(app)
		} else {
			http.Error(w, "PrivacyLens is not running from its app bundle", http.StatusNotFound)
			return
		}
	}
	if err := openDiskAccessSettings(reveal); err != nil {
		http.Error(w, "could not open System Settings: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
