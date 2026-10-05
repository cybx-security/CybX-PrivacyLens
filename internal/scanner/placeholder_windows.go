package scanner

import (
	"os"
	"syscall"
)

// Windows file-attribute bits marking cloud placeholders (OneDrive Files
// On-Demand and similar sync engines). Reading such a file doesn't read the
// disk — it triggers a network download ("hydration") of the full content.
const (
	fileAttributeOffline            = 0x00001000
	fileAttributeRecallOnOpen       = 0x00040000
	fileAttributeRecallOnDataAccess = 0x00400000
)

// isCloudPlaceholder reports whether the file's content is not actually
// local: opening or reading it would make the sync engine download it.
func isCloudPlaceholder(fi os.FileInfo) bool {
	d, ok := fi.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return false
	}
	const placeholder = fileAttributeOffline | fileAttributeRecallOnOpen | fileAttributeRecallOnDataAccess
	return d.FileAttributes&placeholder != 0
}
