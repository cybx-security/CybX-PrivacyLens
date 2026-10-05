package report

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/rdataback/privacylens/internal/paths"
)

// SavedPaths lists where SaveDefaults wrote the scan results. FindingsLog
// is filled in by the caller, which streams events there during the scan
// via OpenFindingsStream.
type SavedPaths struct {
	HTML        string `json:"html"`
	JSON        string `json:"json"`
	FindingsLog string `json:"findings_log"`
}

// SaveDefaults writes the timestamped HTML and JSON archive reports to the
// per-user data directory so no scan is ever silently lost. The NDJSON
// findings log is NOT written here: events stream to it while the scan
// runs (see OpenFindingsStream), so a log shipper such as a Wazuh agent
// ingests findings continuously instead of one huge end-of-scan burst.
// Masking follows the report's setting.
func SaveDefaults(r *Report) (SavedPaths, error) {
	var saved SavedPaths

	reportsDir, err := paths.ReportsDir()
	if err != nil {
		return saved, fmt.Errorf("cannot create reports directory: %w", err)
	}
	stamp := r.GeneratedAt.Format("2006-01-02_150405")

	htmlPath := filepath.Join(reportsDir, "scan-"+stamp+".html")
	f, err := os.Create(htmlPath)
	if err != nil {
		return saved, err
	}
	werr := WriteHTML(f, r)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return saved, fmt.Errorf("writing %s: %w", htmlPath, werr)
	}
	saved.HTML = htmlPath

	jsonPath := filepath.Join(reportsDir, "scan-"+stamp+".json")
	f, err = os.Create(jsonPath)
	if err != nil {
		return saved, err
	}
	werr = WriteJSON(f, r)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return saved, fmt.Errorf("writing %s: %w", jsonPath, werr)
	}
	saved.JSON = jsonPath
	return saved, nil
}
