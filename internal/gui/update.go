package gui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/rdataback/privacylens/internal/update"
)

// Indirections so tests can drive the update flow without GitHub, a
// download, or an installer.
var (
	checkRelease     = update.Check
	downloadRelease  = update.Download
	installRelease   = update.Install
	relaunchApp      = update.Relaunch
	installedVersion = update.InstalledAppVersion
	strayCopy        = update.StrayCopy
)

// updateState is what /api/update/status reports while an update runs.
type updateState struct {
	// Phase: idle, downloading, installing, relaunching, done, manual, error.
	Phase   string `json:"phase"`
	Version string `json:"version,omitempty"` // version being installed
	Done    int64  `json:"done"`
	Total   int64  `json:"total"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
	// Installer and Steps are set in the manual phase (Linux): where the
	// verified archive is and the commands that finish the job.
	Installer string `json:"installer,omitempty"`
	Steps     string `json:"steps,omitempty"`
}

type updater struct {
	mu    sync.Mutex
	state updateState
	rel   *update.Release // the newer release the last check found
}

func (u *updater) set(f func(st *updateState)) {
	u.mu.Lock()
	f(&u.state)
	u.mu.Unlock()
}

// handleUpdateCheck asks GitHub for the latest release and reports it
// against the running version.
func (s *server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	type reply struct {
		Current     string    `json:"current"`
		Latest      string    `json:"latest,omitempty"`
		Available   bool      `json:"available"`
		Notes       string    `json:"notes,omitempty"`
		URL         string    `json:"url,omitempty"`
		PublishedAt time.Time `json:"published_at,omitempty"`
		Asset       string    `json:"asset,omitempty"`
		Size        int64     `json:"size,omitempty"`
		Manual      bool      `json:"manual"` // no silent installer on this OS
		Error       string    `json:"error,omitempty"`
		// StrayCopy is set when this window runs from a bundle other than
		// the installed one (an old download): updates land in the
		// installed copy, so the person should switch to it.
		StrayCopy        string `json:"stray_copy,omitempty"`
		InstalledVersion string `json:"installed_version,omitempty"`
	}
	out := reply{Current: s.opts.Version, Manual: runtime.GOOS != "darwin" && runtime.GOOS != "windows"}
	if running, installed := strayCopy(); running != "" {
		out.StrayCopy, out.InstalledVersion = running, update.InstalledAppVersion(installed)
	}
	w.Header().Set("Content-Type", "application/json")
	if s.opts.UpdateRepo == "" {
		out.Error = "this build has no update source configured"
		json.NewEncoder(w).Encode(out)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	rel, newer, err := checkRelease(ctx, s.opts.UpdateRepo, s.opts.Version)
	if rel != nil {
		out.Latest, out.Notes, out.URL, out.PublishedAt = rel.Version, rel.Notes, rel.URL, rel.PublishedAt
		out.Asset, out.Size = rel.Asset.Name, rel.Asset.Size
	}
	if err != nil {
		out.Error = err.Error()
	}
	out.Available = newer && err == nil
	s.upd.mu.Lock()
	if out.Available {
		s.upd.rel = rel
	} else {
		s.upd.rel = nil
	}
	s.upd.mu.Unlock()
	json.NewEncoder(w).Encode(out)
}

// handleUpdateInstall starts installing the release the last check found.
// Refused while a scan runs: the installer stops this process.
func (s *server) handleUpdateInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	s.progMu.Lock()
	scanning := s.prog.Active
	s.progMu.Unlock()
	if scanning {
		http.Error(w, "a scan is running; wait for it to finish or cancel it, then update", http.StatusConflict)
		return
	}
	s.upd.mu.Lock()
	rel := s.upd.rel
	busy := s.upd.state.Phase != "" && s.upd.state.Phase != "idle" && s.upd.state.Phase != "error"
	if rel == nil || busy {
		s.upd.mu.Unlock()
		if busy {
			http.Error(w, "an update is already in progress", http.StatusConflict)
		} else {
			http.Error(w, "check for updates first", http.StatusBadRequest)
		}
		return
	}
	s.upd.state = updateState{Phase: "downloading", Version: rel.Version, Total: rel.Asset.Size}
	s.upd.mu.Unlock()
	go s.runUpdate(rel)
	w.WriteHeader(http.StatusAccepted)
}

func (s *server) handleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	s.upd.mu.Lock()
	st := s.upd.state
	s.upd.mu.Unlock()
	if st.Phase == "" {
		st.Phase = "idle"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(st)
}

// runUpdate downloads, verifies, and installs rel, then hands over to the
// new version: on macOS by opening the new app and stopping this one; on
// Windows the setup wizard stops this process itself and reopens the app.
func (s *server) runUpdate(rel *update.Release) {
	fail := func(err error) {
		s.upd.set(func(st *updateState) { st.Phase, st.Error = "error", err.Error() })
	}
	dir, err := os.MkdirTemp("", "privacylens-update-")
	if err != nil {
		fail(err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	path, err := downloadRelease(ctx, rel, dir, func(done, total int64) {
		s.upd.set(func(st *updateState) { st.Done, st.Total = done, total })
	})
	if err != nil {
		os.RemoveAll(dir)
		fail(err)
		return
	}
	msg := "Installing…"
	switch runtime.GOOS {
	case "darwin":
		msg = "macOS is asking for your password to install the update."
	case "windows":
		msg = "Windows is asking for permission. Setup then closes PrivacyLens and reopens it when it is done."
	}
	s.upd.set(func(st *updateState) { st.Phase, st.Message = "installing", msg })
	err = installRelease(ctx, path, true)
	switch {
	case errors.Is(err, update.ErrManual):
		s.upd.set(func(st *updateState) {
			st.Phase, st.Installer, st.Steps = "manual", path, update.ManualSteps(path)
			st.Message = "Downloaded and verified. Finish the update in a terminal:"
		})
		return
	case err != nil:
		os.RemoveAll(dir)
		fail(err)
		return
	}
	if runtime.GOOS == "windows" {
		// Setup is running elevated and will terminate this process any
		// moment; whatever the page sees last should already say so.
		s.upd.set(func(st *updateState) {
			st.Phase, st.Message = "done", "Setup is running. PrivacyLens reopens by itself when it finishes — you can close this tab."
		})
		return
	}
	os.RemoveAll(dir)
	// Trust, but verify: the installer ran, so the installed app must now
	// carry the new version. If it does not, say so instead of reopening
	// an old copy and calling it done.
	if got := installedVersion(update.InstalledApp); got != "" && update.CompareVersions(got, rel.Version) < 0 {
		fail(fmt.Errorf("the installer finished but %s is still version %s, not %s; run the installer from the download page, then open PrivacyLens from Applications", update.InstalledApp, got, rel.Version))
		return
	}
	s.upd.set(func(st *updateState) { st.Phase, st.Message = "relaunching", "Installed. Opening the new version…" })
	opened, reopened := relaunchApp()
	s.upd.set(func(st *updateState) {
		st.Phase = "done"
		switch {
		case reopened && update.AppBundle() != "" && opened != update.AppBundle():
			st.Message = fmt.Sprintf("Updated to v%s and reopened from %s in a new browser tab — you can close this one. This window was running an old copy at %s; delete that copy so it is not opened again.", rel.Version, opened, update.AppBundle())
		case reopened:
			st.Message = fmt.Sprintf("Updated to v%s. PrivacyLens has reopened in a new browser tab — you can close this one.", rel.Version)
		default:
			st.Message = fmt.Sprintf("Updated to v%s. Start PrivacyLens again to use the new version.", rel.Version)
		}
	})
	// Let the page collect the final status before this version goes away.
	time.Sleep(3 * time.Second)
	s.shutdown()
}
