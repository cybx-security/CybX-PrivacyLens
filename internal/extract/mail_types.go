// Mail-store types and detection shared by every architecture. Two kinds
// of store exist: Outlook for Windows' .pst/.ost files (read in mail.go by
// go-pst on 64-bit; mail_stub.go on 32-bit, where go-pst's io_uring
// dependency does not compile), and Outlook for Mac's message store, which
// is not a database file at all but one MIME file per message
// (.olk15MsgSource; mail_mime.go, every architecture).
package extract

import (
	"path/filepath"
	"strings"
)

// IsMailStore reports whether path is Outlook mailbox data: a .pst/.ost
// store, or one message of Outlook for Mac's store.
func IsMailStore(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".pst", ".ost":
		return true
	}
	return IsMessageSource(path)
}

// IsMessageSource reports whether path is one message from Outlook for
// Mac's store: the raw MIME source Outlook keeps per message under
// ~/Library/Group Containers/UBF8T346G9.Office/Outlook/Outlook 15 Profiles/
// <profile>/Data/Message Sources (.olk15MsgSource; Outlook 2011 wrote
// .olk14MsgSource).
func IsMessageSource(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".olk15msgsource", ".olk14msgsource":
		return true
	}
	return false
}

// MailStoreDisplayPath is the path to list a mail store under when it is
// reported as not searched. A .pst/.ost is listed as itself; Outlook for
// Mac's thousands of per-message files collapse to their profile folder,
// so a normal scan of a Mac home folder names the mailbox once instead of
// listing every message in it.
func MailStoreDisplayPath(path string) string {
	if !IsMessageSource(path) {
		return path
	}
	if dir := outlookMacProfileDir(path); dir != "" {
		return dir
	}
	return filepath.Dir(path)
}

// outlookMacProfileDir returns the Outlook for Mac profile folder a
// message file sits in (".../Outlook 15 Profiles/Main Profile"), or "".
func outlookMacProfileDir(path string) string {
	const marker = "Outlook 15 Profiles"
	parts := strings.Split(filepath.Clean(path), string(filepath.Separator))
	for i, p := range parts {
		if p == marker && i+1 < len(parts)-1 {
			return strings.Join(parts[:i+2], string(filepath.Separator))
		}
	}
	return ""
}

// outlookMacFolder names the mailbox a message file belongs to, for the
// Folder column of its findings. Outlook keeps the mail-folder tree in a
// SQLite database, not on the filesystem, so the profile is as close as
// the files alone can get.
func outlookMacFolder(path string) string {
	if dir := outlookMacProfileDir(path); dir != "" {
		return "Outlook for Mac — " + filepath.Base(dir)
	}
	return "Outlook for Mac"
}

// MailItem is one message (or contact, appointment, task, …) from a mail
// store, flattened to scannable text.
type MailItem struct {
	Folder  string
	Subject string
	Index   int    // 1-based position within its folder
	Text    string // subject, sender, recipients, and body, newline-joined
}

// ReadMailStore extracts every item from a mail store: all messages of a
// .pst/.ost, or the single message of an Outlook for Mac message file. A
// partially corrupt store still yields whatever was readable: the items
// read so far are returned alongside the first error encountered, and the
// caller decides whether partial coverage is worth reporting.
func ReadMailStore(path string) ([]MailItem, error) {
	if IsMessageSource(path) {
		return readMessageSource(path)
	}
	return readPSTStore(path)
}
