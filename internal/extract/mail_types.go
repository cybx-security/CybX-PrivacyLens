// Mail-store types and detection shared by every architecture. The actual
// reader lives in mail.go (64-bit; pure-Go go-pst) with a stub in
// mail_stub.go for 32-bit builds, where go-pst's io_uring dependency does
// not compile.
package extract

import (
	"path/filepath"
	"strings"
)

// IsMailStore reports whether path is an Outlook mail store by extension.
func IsMailStore(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".pst", ".ost":
		return true
	}
	return false
}

// MailItem is one message (or contact, appointment, task, …) from a mail
// store, flattened to scannable text.
type MailItem struct {
	Folder  string
	Subject string
	Index   int    // 1-based position within its folder
	Text    string // subject, sender, recipients, and body, newline-joined
}
