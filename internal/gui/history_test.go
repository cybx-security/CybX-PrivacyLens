package gui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A scan run from the GUI records its settings, shows up in the history
// list, and can be reopened and re-downloaded from there.
func TestHistoryListsAndReopensSavedScan(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("PRIVACYLENS_DATA_DIR", dataDir)
	s := &server{
		opts:   Options{Tool: "PrivacyLens", Version: "test"},
		sysLog: filepath.Join(t.TempDir(), "not-installed", "findings.json"),
	}
	root := scanFixture(t)
	body, _ := json.Marshal(map[string]any{
		"paths": []string{root}, "excludes": []string{"*.bak"}, "min_confidence": "medium", "ocr": true,
	})
	rr := httptest.NewRecorder()
	s.handleScan(rr, httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(string(body))))
	if rr.Code != http.StatusOK {
		t.Fatalf("scan status = %d: %s", rr.Code, rr.Body)
	}
	var live struct {
		Params   map[string]any `json:"params"`
		Settings []struct{ Label, Value string }
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &live); err != nil {
		t.Fatal(err)
	}
	if live.Params["source"] != "gui" || live.Params["min_confidence"] != "medium" || live.Params["ocr"] != true {
		t.Errorf("params = %v, want gui/medium/ocr", live.Params)
	}
	if len(live.Settings) == 0 || !strings.Contains(rr.Body.String(), `"label":"Excluded patterns","value":"*.bak"`) {
		t.Errorf("settings rows missing from scan response: %s", rr.Body)
	}

	// Plus an older report without params, to make sure it still lists.
	old := filepath.Join(dataDir, "reports", "scan-2025-01-01_000000.json")
	if err := os.WriteFile(old, []byte(`{"tool":"PrivacyLens","version":"0.5","generated_at":"2025-01-01T00:00:00Z","roots":["/old"],"masked":true,"duration":"1s","stats":{"files_scanned":3},"findings":[{"category":"SSN"},{"category":"SSN"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// And junk that must be ignored, never served.
	os.WriteFile(filepath.Join(dataDir, "reports", "notes.json"), []byte(`{}`), 0o600)

	rr = httptest.NewRecorder()
	s.handleHistory(rr, httptest.NewRequest(http.MethodGet, "/api/history", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("history status = %d: %s", rr.Code, rr.Body)
	}
	var hist struct {
		Dir     string
		Reports []historyEntry
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &hist); err != nil {
		t.Fatal(err)
	}
	if len(hist.Reports) != 2 {
		t.Fatalf("history = %+v, want 2 reports", hist.Reports)
	}
	newest, oldest := hist.Reports[0], hist.Reports[1]
	if newest.Findings != 1 || newest.Params == nil || newest.Params.Source != "gui" || newest.HTML == "" {
		t.Errorf("newest = %+v, want 1 finding with gui params and an HTML sibling", newest)
	}
	if oldest.Findings != 2 || oldest.FilesScanned != 3 || oldest.Params != nil || oldest.HTML != "" {
		t.Errorf("oldest = %+v, want 2 findings, 3 files, no params, no HTML", oldest)
	}

	// Reopen the newest: same shape as /api/scan.
	rr = httptest.NewRecorder()
	s.handleHistoryReport(rr, httptest.NewRequest(http.MethodGet, "/api/history/report?name="+newest.Name, nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"category":"SSN"`) || strings.Contains(rr.Body.String(), "219-09-9999") {
		t.Fatalf("reopen status = %d, body must have the masked SSN finding: %s", rr.Code, rr.Body)
	}
	// Re-download it as CSV.
	rr = httptest.NewRecorder()
	s.handleDownload(rr, httptest.NewRequest(http.MethodGet, "/api/download?format=csv&report="+newest.Name, nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "SSN") {
		t.Fatalf("download status = %d: %s", rr.Code, rr.Body)
	}

	// Anything outside the naming scheme is refused before touching disk.
	for _, bad := range []string{"../gui-settings.json", "notes.json", "scan-2025-01-01_000000.html", ""} {
		rr = httptest.NewRecorder()
		s.handleHistoryReport(rr, httptest.NewRequest(http.MethodGet, "/api/history/report?name="+bad, nil))
		if rr.Code != http.StatusBadRequest {
			t.Errorf("name %q: status = %d, want 400", bad, rr.Code)
		}
	}
	rr = httptest.NewRecorder()
	s.handleHistoryReport(rr, httptest.NewRequest(http.MethodGet, "/api/history/report?name=scan-2000-01-01_000000.json", nil))
	if rr.Code != http.StatusNotFound {
		t.Errorf("missing report: status = %d, want 404", rr.Code)
	}
}

// The form state round-trips through the data folder and survives a
// damaged file.
func TestSettingsRoundTrip(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("PRIVACYLENS_DATA_DIR", dataDir)
	s := &server{}

	rr := httptest.NewRecorder()
	s.handleSettings(rr, httptest.NewRequest(http.MethodGet, "/api/settings", nil))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("fresh GET status = %d, want 204", rr.Code)
	}

	put := `{"paths":"/Users/me/Documents\n/shared","excludes":"*.bak","exclude_emails":"","min_confidence":"high","max_size_mb":10,"show_full":false,"ocr":true,"include_cloud":false,"scan_all":false,"mail":false,"wazuh_log":true,"categories_off":["SSN"]}`
	rr = httptest.NewRecorder()
	s.handleSettings(rr, httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(put)))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("PUT status = %d: %s", rr.Code, rr.Body)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "gui-settings.json")); err != nil {
		t.Fatal(err)
	}

	rr = httptest.NewRecorder()
	s.handleSettings(rr, httptest.NewRequest(http.MethodGet, "/api/settings", nil))
	var got guiSettings
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &got) != nil {
		t.Fatalf("GET status = %d: %s", rr.Code, rr.Body)
	}
	if got.MinConfidence != "high" || !got.OCR || got.MaxSizeMB != 10 || len(got.CategoriesOff) != 1 || got.CategoriesOff[0] != "SSN" || !strings.Contains(got.Paths, "/shared") {
		t.Errorf("settings = %+v", got)
	}

	rr = httptest.NewRecorder()
	s.handleSettings(rr, httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(`{"paths":"x","bogus":1}`)))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unknown field: status = %d, want 400", rr.Code)
	}

	os.WriteFile(filepath.Join(dataDir, "gui-settings.json"), []byte("{not json"), 0o600)
	rr = httptest.NewRecorder()
	s.handleSettings(rr, httptest.NewRequest(http.MethodGet, "/api/settings", nil))
	if rr.Code != http.StatusNoContent {
		t.Errorf("damaged file: status = %d, want 204", rr.Code)
	}
}
