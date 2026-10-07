package extract

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// MailAttachment is one attachment of a MailItem, extracted to a temporary
// file so the regular document extractors can read it. The file exists
// only while the item is being handled (see WalkMailStore) and is removed
// afterwards: a mailbox's worth of attachments never sits on disk at once,
// and nothing with PII in it is left behind.
type MailAttachment struct {
	Name string // file name as attached
	Path string // temporary copy
	Size int64
}

// maxAttachmentBytes caps what one attachment is extracted to disk; larger
// ones are reported as not searched rather than filling the temp volume.
const maxAttachmentBytes = 256 << 20

// ErrAttachmentTooLarge marks an attachment skipped for its size.
var ErrAttachmentTooLarge = fmt.Errorf("attachment larger than %d MB was not searched", maxAttachmentBytes>>20)

// attachmentScannable reports whether an attachment is worth extracting:
// anything FromFile would read or at least report on. Known-binary types
// such as archives and media are not; images are, since OCR may be on.
func attachmentScannable(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	if imageExts[ext] {
		return true
	}
	return !skipExts[ext]
}

// saveAttachment copies r into dir under a safe name that keeps the
// original extension (FromFile dispatches on it), bounded by
// maxAttachmentBytes.
func saveAttachment(dir string, index int, name string, r io.Reader) (MailAttachment, error) {
	base := filepath.Base(strings.NewReplacer("\\", "_", "/", "_", "\x00", "_").Replace(name))
	if base == "" || base == "." {
		base = "attachment"
	}
	path := filepath.Join(dir, fmt.Sprintf("%d-%s", index, base))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return MailAttachment{}, err
	}
	n, err := io.Copy(f, io.LimitReader(r, maxAttachmentBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxAttachmentBytes {
		err = ErrAttachmentTooLarge
	}
	if err != nil {
		os.Remove(path)
		return MailAttachment{}, err
	}
	return MailAttachment{Name: name, Path: path, Size: n}, nil
}

// attachmentDir is the per-item temporary directory for extracted
// attachments; "" (with no error) when the item has none to extract.
func attachmentDir() (string, error) {
	return os.MkdirTemp("", "privacylens-mail-")
}
