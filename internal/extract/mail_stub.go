//go:build arm || 386

// 32-bit stub: the go-pst mail reader depends on go-uring, which does not
// compile on 32-bit architectures. Mail stores are still recognized (so
// they are counted and listed as not searched), but a targeted mail scan
// reports a clear per-file error instead of findings.
package extract

import "errors"

// ReadMailStore is unavailable on 32-bit builds.
func ReadMailStore(path string) ([]MailItem, error) {
	return nil, errors.New("Outlook mail scanning is not supported on 32-bit builds of PrivacyLens; run the scan from a 64-bit machine")
}
