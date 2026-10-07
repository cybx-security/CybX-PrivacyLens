//go:build arm || 386

// 32-bit stub: the go-pst mail reader depends on go-uring, which does not
// compile on 32-bit architectures. .pst/.ost stores are still recognized
// (so they are counted and listed as not searched), but a targeted mail
// scan reports a clear per-file error instead of findings. Outlook for
// Mac message files need no go-pst and read fine on every architecture.
package extract

import "errors"

// walkPSTStore is unavailable on 32-bit builds.
func walkPSTStore(path string, fn func(MailItem)) error {
	return errors.New("Outlook mail scanning is not supported on 32-bit builds of PrivacyLens; run the scan from a 64-bit machine")
}
