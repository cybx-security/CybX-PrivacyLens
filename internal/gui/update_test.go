package gui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rdataback/privacylens/internal/update"
)

func TestUpdateCheckAndInstallFlow(t *testing.T) {
	saved := []any{checkRelease, downloadRelease, installRelease, relaunchApp, installedVersion, strayCopy}
	t.Cleanup(func() {
		checkRelease = saved[0].(func(context.Context, string, string) (*update.Release, bool, error))
		downloadRelease = saved[1].(func(context.Context, *update.Release, string, func(int64, int64)) (string, error))
		installRelease = saved[2].(func(context.Context, string, bool) error)
		relaunchApp = saved[3].(func() (string, bool))
		installedVersion = saved[4].(func(string) string)
		strayCopy = saved[5].(func() (string, string))
	})
	installedVersion = func(string) string { return "0.9.11" } // what the installer leaves behind
	strayCopy = func() (string, string) { return "", "" }
	rel := &update.Release{Version: "0.9.11", Tag: "v0.9.11", Notes: "notes", Asset: update.Asset{Name: "x.pkg", Size: 10}}
	checkRelease = func(ctx context.Context, repo, current string) (*update.Release, bool, error) {
		if repo != "acme/pl" {
			t.Errorf("repo = %q", repo)
		}
		return rel, update.CompareVersions(rel.Version, current) > 0, nil
	}
	installed, relaunched := "", false
	downloadRelease = func(ctx context.Context, r *update.Release, dir string, progress func(int64, int64)) (string, error) {
		progress(10, 10)
		p := filepath.Join(dir, r.Asset.Name)
		return p, os.WriteFile(p, []byte("pkg"), 0o600)
	}
	installRelease = func(ctx context.Context, path string, relaunch bool) error { installed = path; return nil }
	relaunchApp = func() (string, bool) { relaunched = true; return update.InstalledApp, true }

	s := &server{opts: Options{Version: "0.9.10", UpdateRepo: "acme/pl"}, stop: make(chan struct{})}

	// Install before any check is refused.
	rr := httptest.NewRecorder()
	s.handleUpdateInstall(rr, httptest.NewRequest(http.MethodPost, "/api/update/install", nil))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("install without check: status = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	s.handleUpdateCheck(rr, httptest.NewRequest(http.MethodGet, "/api/update/check", nil))
	var chk struct {
		Current, Latest string
		Available       bool
		Notes           string
	}
	if json.Unmarshal(rr.Body.Bytes(), &chk) != nil || !chk.Available || chk.Latest != "0.9.11" || chk.Current != "0.9.10" || chk.Notes != "notes" {
		t.Fatalf("check = %s", rr.Body)
	}

	// Refused while a scan runs.
	s.prog.Active = true
	rr = httptest.NewRecorder()
	s.handleUpdateInstall(rr, httptest.NewRequest(http.MethodPost, "/api/update/install", nil))
	if rr.Code != http.StatusConflict {
		t.Errorf("install during scan: status = %d", rr.Code)
	}
	s.prog.Active = false

	rr = httptest.NewRecorder()
	s.handleUpdateInstall(rr, httptest.NewRequest(http.MethodPost, "/api/update/install", nil))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("install: status = %d %s", rr.Code, rr.Body)
	}
	deadline := time.Now().Add(5 * time.Second)
	var st updateState
	for time.Now().Before(deadline) {
		rr = httptest.NewRecorder()
		s.handleUpdateStatus(rr, httptest.NewRequest(http.MethodGet, "/api/update/status", nil))
		json.Unmarshal(rr.Body.Bytes(), &st)
		if st.Phase == "done" || st.Phase == "error" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st.Phase != "done" || installed == "" || st.Done != 10 {
		t.Fatalf("final state = %+v installed=%q", st, installed)
	}
	if runtime.GOOS == "windows" {
		// Setup, started elevated, stops this process and reopens the app
		// itself; the server only reports that and leaves the installer in
		// place for Setup to run from.
		if relaunched || !strings.Contains(st.Message, "Setup") {
			t.Errorf("windows: state = %+v relaunched=%v, want Setup hand-off", st, relaunched)
		}
	} else {
		if !strings.Contains(st.Message, "0.9.11") || !relaunched {
			t.Errorf("state = %+v relaunched=%v, want relaunch of the new version", st, relaunched)
		}
		if _, err := os.Stat(filepath.Dir(installed)); !errors.Is(err, os.ErrNotExist) {
			t.Error("temp download dir should be removed after install")
		}
	}

	// Same version: no update offered.
	s.opts.Version = "0.9.11"
	rr = httptest.NewRecorder()
	s.handleUpdateCheck(rr, httptest.NewRequest(http.MethodGet, "/api/update/check", nil))
	if !strings.Contains(rr.Body.String(), `"available":false`) {
		t.Errorf("same version offered as update: %s", rr.Body)
	}
}

func TestUpdateCheckWithoutRepo(t *testing.T) {
	s := &server{opts: Options{Version: "0.9.10"}}
	rr := httptest.NewRecorder()
	s.handleUpdateCheck(rr, httptest.NewRequest(http.MethodGet, "/api/update/check", nil))
	if !strings.Contains(rr.Body.String(), "no update source") {
		t.Errorf("body = %s", rr.Body)
	}
}

// An installer that ran but left the old version in place is an error,
// never a relaunch of the old copy.
func TestUpdateRefusesWhenInstallDidNotTake(t *testing.T) {
	saved := []any{checkRelease, downloadRelease, installRelease, relaunchApp, installedVersion}
	t.Cleanup(func() {
		checkRelease = saved[0].(func(context.Context, string, string) (*update.Release, bool, error))
		downloadRelease = saved[1].(func(context.Context, *update.Release, string, func(int64, int64)) (string, error))
		installRelease = saved[2].(func(context.Context, string, bool) error)
		relaunchApp = saved[3].(func() (string, bool))
		installedVersion = saved[4].(func(string) string)
	})
	if runtime.GOOS == "windows" {
		t.Skip("Windows hands off to Setup before this check")
	}
	rel := &update.Release{Version: "0.9.14", Asset: update.Asset{Name: "x.pkg", Size: 1}}
	checkRelease = func(context.Context, string, string) (*update.Release, bool, error) { return rel, true, nil }
	downloadRelease = func(ctx context.Context, r *update.Release, dir string, progress func(int64, int64)) (string, error) {
		p := filepath.Join(dir, r.Asset.Name)
		return p, os.WriteFile(p, []byte("pkg"), 0o600)
	}
	installRelease = func(context.Context, string, bool) error { return nil }
	installedVersion = func(string) string { return "0.9.13" } // did not change
	relaunched := false
	relaunchApp = func() (string, bool) { relaunched = true; return update.InstalledApp, true }

	s := &server{opts: Options{Version: "0.9.13", UpdateRepo: "acme/pl"}, stop: make(chan struct{})}
	rr := httptest.NewRecorder()
	s.handleUpdateCheck(rr, httptest.NewRequest(http.MethodGet, "/api/update/check", nil))
	rr = httptest.NewRecorder()
	s.handleUpdateInstall(rr, httptest.NewRequest(http.MethodPost, "/api/update/install", nil))
	deadline := time.Now().Add(5 * time.Second)
	var st updateState
	for time.Now().Before(deadline) {
		rr = httptest.NewRecorder()
		s.handleUpdateStatus(rr, httptest.NewRequest(http.MethodGet, "/api/update/status", nil))
		json.Unmarshal(rr.Body.Bytes(), &st)
		if st.Phase == "done" || st.Phase == "error" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st.Phase != "error" || !strings.Contains(st.Error, "still version 0.9.13") || relaunched {
		t.Fatalf("state = %+v relaunched=%v, want an error and no relaunch", st, relaunched)
	}
}
