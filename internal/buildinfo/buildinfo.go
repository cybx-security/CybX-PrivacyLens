// Package buildinfo holds the product identity shared by every binary (the
// CLI and the GUI launcher), so a release bumps the version in one place.
package buildinfo

const (
	Tool    = "PrivacyLens"
	Version = "0.9.15"
	// UpdateRepo is the GitHub repository whose Releases carry new
	// versions (owner/name). It must be public: customer machines fetch
	// the latest release and its installers anonymously. A private source
	// repo can publish to a separate public releases-only repo.
	UpdateRepo = "cybx-security/CybX-PrivacyLens"
)
