package gui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rdataback/privacylens/internal/update"
)

func TestUpdateCheckAndInstallFlow(t *testing.T) {
	saved := []any{checkRelease, downloadRelease, installRelease, relaunchApp}
	t.Cleanup(func() {
		checkRelease = saved[0].(func(context.Context, string, string) (*update.Release, bool, error))
		downloadRelease = saved[1].(func(context.Context, *update.Release, string, func(int64, int64)) (string, error))
		installRelease = saved[2].(func(context.Context, string, bool) error)
		relaunchApp = saved[3].(func() bool)
	})
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
	relaunchApp = func() bool { relaunched = true; return true }

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
	if st.Phase != "done" || !strings.Contains(st.Message, "0.9.11") || installed == "" || !relaunched || st.Done != 10 {
		t.Fatalf("final state = %+v installed=%q relaunched=%v", st, installed, relaunched)
	}
	if _, err := os.Stat(filepath.Dir(installed)); !errors.Is(err, os.ErrNotExist) {
		t.Error("temp download dir should be removed after install")
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
