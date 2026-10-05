//go:build !windows && !darwin

package scanner

import "os"

// isCloudPlaceholder: no cloud-placeholder convention to detect on this
// platform; every regular file's content is assumed local.
func isCloudPlaceholder(os.FileInfo) bool { return false }
