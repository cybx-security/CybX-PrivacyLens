package scanner

import (
	"os"
	"syscall"
)

// sfDataless marks a file whose content lives in iCloud (or another file
// provider) rather than on disk — "Optimize Mac Storage" evicted it.
// Reading it would trigger a download.
const sfDataless = 0x40000000 // SF_DATALESS from sys/stat.h

// isCloudPlaceholder reports whether the file's content is not actually
// local: reading it would make the file provider download it.
func isCloudPlaceholder(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return st.Flags&sfDataless != 0
}
