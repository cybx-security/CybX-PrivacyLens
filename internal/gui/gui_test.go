package gui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSecurityHeaders(t *testing.T) {
	h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	for _, name := range []string{"Cache-Control", "Content-Security-Policy", "Referrer-Policy", "X-Content-Type-Options", "X-Frame-Options"} {
		if rr.Header().Get(name) == "" {
			t.Errorf("missing %s", name)
		}
	}
}

func TestAuthRequiresToken(t *testing.T) {
	s := &server{token: "secret"}
	h := s.auth(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodGet, "/api/progress", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/progress", nil)
	req.Header.Set("X-PL-Token", "secret")
	h(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestScanRejectsUnknownFields(t *testing.T) {
	s := &server{opts: Options{Tool: "PrivacyLens", Version: "test"}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(`{"paths":["."],"typo":true}`))
	s.handleScan(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rr.Code)
	}
}

// scanResponse is the slice of the /api/scan reply these tests check.
type scanResponse struct {
	Findings []struct {
		Category string `json:"category"`
	} `json:"findings"`
	Saved *struct {
		FindingsLog string `json:"findings_log"`
	} `json:"saved"`
	SaveError  string `json:"save_error"`
	LogWarning string `json:"log_warning"`
}

func runScan(t *testing.T, s *server, root string) scanResponse {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"paths": []string{root}})
	rr := httptest.NewRecorder()
	s.handleScan(rr, httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(string(body))))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body)
	}
	var resp scanResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func scanFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "hr.txt"), []byte("Employee SSN: 219-09-9999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

// On a machine that never ran the installer the GUI must use the per-user
// log quietly, exactly like the CLI — no Insights warning on every scan.
func TestScanQuietFallbackWithoutInstaller(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("PRIVACYLENS_DATA_DIR", dataDir)
	s := &server{
		opts:   Options{Tool: "PrivacyLens", Version: "test"},
		sysLog: filepath.Join(t.TempDir(), "not-installed", "findings.json"),
	}
	resp := runScan(t, s, scanFixture(t))
	if len(resp.Findings) != 1 || resp.Findings[0].Category != "SSN" {
		t.Fatalf("findings = %+v, want one SSN", resp.Findings)
	}
	if resp.LogWarning != "" || resp.SaveError != "" {
		t.Errorf("log_warning=%q save_error=%q, want neither", resp.LogWarning, resp.SaveError)
	}
	if resp.Saved == nil || !strings.HasPrefix(resp.Saved.FindingsLog, dataDir) {
		t.Errorf("saved = %+v, want findings log under %s", resp.Saved, dataDir)
	}
}

// When the installer's log directory exists, the GUI streams there.
func TestScanUsesSystemLogWhenInstalled(t *testing.T) {
	t.Setenv("PRIVACYLENS_DATA_DIR", t.TempDir())
	sysLog := filepath.Join(t.TempDir(), "findings.json")
	s := &server{opts: Options{Tool: "PrivacyLens", Version: "test"}, sysLog: sysLog}
	resp := runScan(t, s, scanFixture(t))
	if resp.LogWarning != "" || resp.Saved == nil || resp.Saved.FindingsLog != sysLog {
		t.Fatalf("log_warning=%q saved=%+v, want events in %s", resp.LogWarning, resp.Saved, sysLog)
	}
	b, err := os.ReadFile(sysLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"privacylens_event":"finding"`) || !strings.Contains(string(b), `"privacylens_event":"scan_summary"`) {
		t.Errorf("system log missing finding or scan_summary events:\n%s", b)
	}
}

// Installed but unwritable: fall back to the per-user log AND say so.
func TestScanLoudFallbackWhenSystemLogUnwritable(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions and a non-root user")
	}
	dataDir := t.TempDir()
	t.Setenv("PRIVACYLENS_DATA_DIR", dataDir)
	sysDir := t.TempDir()
	if err := os.Chmod(sysDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(sysDir, 0o755) })
	s := &server{opts: Options{Tool: "PrivacyLens", Version: "test"}, sysLog: filepath.Join(sysDir, "findings.json")}
	resp := runScan(t, s, scanFixture(t))
	if !strings.Contains(resp.LogWarning, "Insights will NOT see this scan") {
		t.Errorf("log_warning = %q, want loud Insights warning", resp.LogWarning)
	}
	if resp.Saved == nil || !strings.HasPrefix(resp.Saved.FindingsLog, dataDir) {
		t.Errorf("saved = %+v, want per-user fallback under %s", resp.Saved, dataDir)
	}
}

// The pre-filled scan path is user data and must be HTML-escaped.
func TestIndexEscapesDefaultPath(t *testing.T) {
	home := filepath.Join(t.TempDir(), "R&D <x>")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	s := &server{opts: Options{Tool: "PrivacyLens", Version: "test"}}
	rr := httptest.NewRecorder()
	s.handleIndex(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	page := rr.Body.String()
	if strings.Contains(page, "R&D <x>") || !strings.Contains(page, "R&amp;D &lt;x&gt;") {
		t.Error("default path was not HTML-escaped in the page")
	}
}

func stopped(s *server) bool {
	select {
	case <-s.stop:
		return true
	default:
		return false
	}
}

// The idle watchdog stops the server once no page has made contact, but
// never while a scan is running.
func TestIdleWatchdog(t *testing.T) {
	s := &server{stop: make(chan struct{})}
	s.prog.Active = true
	go s.watchIdle(20*time.Millisecond, 5*time.Millisecond)
	time.Sleep(80 * time.Millisecond)
	if stopped(s) {
		t.Fatal("watchdog stopped the server during a scan")
	}
	s.progMu.Lock()
	s.prog.Active = false
	s.progMu.Unlock()
	select {
	case <-s.stop:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog never stopped an idle server")
	}
}

// Any authenticated request counts as contact and resets the idle clock.
func TestAuthResetsIdle(t *testing.T) {
	s := &server{token: "secret", stop: make(chan struct{})}
	s.idleTicks.Store(7)
	req := httptest.NewRequest(http.MethodGet, "/api/ping", nil)
	req.Header.Set("X-PL-Token", "secret")
	rr := httptest.NewRecorder()
	s.auth(s.handlePing)(rr, req)
	if rr.Code != http.StatusNoContent || s.idleTicks.Load() != 0 {
		t.Fatalf("status = %d, idleTicks = %d", rr.Code, s.idleTicks.Load())
	}
}

func TestQuitStopsServer(t *testing.T) {
	s := &server{stop: make(chan struct{})}
	rr := httptest.NewRecorder()
	s.handleQuit(rr, httptest.NewRequest(http.MethodGet, "/api/quit", nil))
	if rr.Code != http.StatusMethodNotAllowed || stopped(s) {
		t.Fatalf("GET must not quit (status %d)", rr.Code)
	}
	rr = httptest.NewRecorder()
	s.handleQuit(rr, httptest.NewRequest(http.MethodPost, "/api/quit", nil))
	if rr.Code != http.StatusNoContent || !stopped(s) {
		t.Fatalf("POST should quit (status %d)", rr.Code)
	}
	s.handleQuit(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/quit", nil)) // second quit must not panic
}
