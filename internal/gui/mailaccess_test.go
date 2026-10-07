package gui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMailAccessReportsOutlookFolder(t *testing.T) {
	saved := outlookLocations
	t.Cleanup(func() { outlookLocations = saved })

	// No Outlook data at all.
	outlookLocations = func() []string { return []string{filepath.Join(t.TempDir(), "nope")} }
	if ma := checkMailAccess(); ma.Present || ma.NeedsFullDiskAccess {
		t.Errorf("missing folder reported as present: %+v", ma)
	}

	// Present and readable.
	loc := filepath.Join(t.TempDir(), "Outlook 15 Profiles")
	if err := os.MkdirAll(loc, 0o700); err != nil {
		t.Fatal(err)
	}
	outlookLocations = func() []string { return []string{loc} }
	ma := checkMailAccess()
	if !ma.Present || !ma.Readable || ma.NeedsFullDiskAccess || ma.Location != loc {
		t.Errorf("readable folder: %+v", ma)
	}

	// Present but unreadable: on macOS that is the Full Disk Access case.
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		return
	}
	if err := os.Chmod(loc, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(loc, 0o700) })
	ma = checkMailAccess()
	if !ma.Present || ma.Readable {
		t.Errorf("unreadable folder: %+v", ma)
	}
	if runtime.GOOS == "darwin" && (!ma.NeedsFullDiskAccess || ma.GrantTo == "") {
		t.Errorf("macOS must ask for Full Disk Access and name the app: %+v", ma)
	}

	s := &server{}
	rr := httptest.NewRecorder()
	s.handleMailAccess(rr, httptest.NewRequest(http.MethodGet, "/api/mailaccess", nil))
	var got mailAccess
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &got) != nil || got.OS != runtime.GOOS {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body)
	}
}

func TestOpenDiskAccessSettings(t *testing.T) {
	opened := ""
	saved := openDiskAccessSettings
	openDiskAccessSettings = func(reveal string) error { opened = "settings:" + reveal; return nil }
	t.Cleanup(func() { openDiskAccessSettings = saved })
	s := &server{}

	rr := httptest.NewRecorder()
	s.handleOpenDiskAccess(rr, httptest.NewRequest(http.MethodGet, "/api/mailaccess/settings", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	s.handleOpenDiskAccess(rr, httptest.NewRequest(http.MethodPost, "/api/mailaccess/settings", nil))
	if runtime.GOOS == "darwin" {
		if rr.Code != http.StatusNoContent || opened != "settings:" {
			t.Errorf("status = %d opened = %q", rr.Code, opened)
		}
	} else if rr.Code != http.StatusNotFound {
		t.Errorf("non-macOS status = %d, want 404", rr.Code)
	}
}
