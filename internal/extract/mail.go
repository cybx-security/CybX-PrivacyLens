//go:build !arm && !386

// Outlook mail-store extraction (.pst/.ost) for targeted mail scans. The
// stores are read in pure Go via go-pst — no Outlook, MAPI, or CGo — which
// preserves the trivial cross-compiles (64-bit only: go-pst's io_uring
// dependency does not compile on 32-bit, see mail_stub.go). Reading is
// strictly read-only, but a live .ost is locked by a running Outlook; those
// surface as file errors.
package extract

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	charsets "github.com/emersion/go-message/charset"
	pst "github.com/mooijtech/go-pst/v6/pkg"
	"github.com/mooijtech/go-pst/v6/pkg/properties"
	"github.com/rotisserie/eris"
	"golang.org/x/text/encoding"
)

func init() {
	// Mail stores carry text in many legacy code pages; register the
	// extended charset table so old messages decode instead of erroring.
	pst.ExtendCharsets(func(name string, enc encoding.Encoding) {
		charsets.RegisterEncoding(name, enc)
	})
}

// walkPSTStore delivers every item of a .pst/.ost file to fn (see
// WalkMailStore for the partial-result contract).
func walkPSTStore(path string, fn func(MailItem)) (err error) {
	// go-pst parses attacker-controllable binary structures; a malformed
	// store must degrade to a per-file error, never take down the scan.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("mail store parser crashed: %v", r)
		}
	}()

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	pstFile, err := pst.New(f)
	if err != nil {
		return fmt.Errorf("not readable as a mail store: %w", err)
	}
	defer pstFile.Cleanup()

	var firstErr error
	keep := func(err error) {
		if firstErr == nil && err != nil {
			firstErr = err
		}
	}
	walkErr := pstFile.WalkFolders(func(folder *pst.Folder) error {
		it, err := folder.GetMessageIterator()
		if eris.Is(err, pst.ErrMessagesNotFound) {
			return nil
		}
		if err != nil {
			keep(fmt.Errorf("folder %q: %w", folder.Name, err))
			return nil // a bad folder must not abort its siblings
		}
		index := 0
		for it.Next() {
			index++
			m := it.Value()
			subject, from, date, text := itemText(m)
			if text == "" {
				continue
			}
			item := MailItem{
				Folder: folder.Name, Subject: subject, From: from, Date: date, Index: index, Text: text,
			}
			var dir string
			item.Attachments, dir = pstAttachments(m, func(aerr error) {
				keep(fmt.Errorf("folder %q, message %d (%s): %w", folder.Name, index, subject, aerr))
			})
			deliver(fn, item, dir)
		}
		if err := it.Err(); err != nil {
			keep(fmt.Errorf("folder %q: %w", folder.Name, err))
		}
		return nil
	})
	keep(walkErr)
	return firstErr
}

// pstAttachments extracts a message's scannable attachments to a fresh
// temporary directory, reporting per-attachment problems through warn.
// The directory is "" when nothing was extracted.
func pstAttachments(m *pst.Message, warn func(error)) ([]MailAttachment, string) {
	it, err := m.GetAttachmentIterator()
	if eris.Is(err, pst.ErrAttachmentsNotFound) {
		return nil, ""
	}
	if err != nil {
		warn(fmt.Errorf("attachments: %w", err))
		return nil, ""
	}
	var out []MailAttachment
	dir := ""
	index := 0
	for it.Next() {
		index++
		a := it.Value()
		name := a.GetAttachLongFilename()
		if name == "" {
			name = a.GetAttachFilename()
		}
		if name == "" {
			name = fmt.Sprintf("attachment-%d%s", index, a.GetAttachExtension())
		}
		if !attachmentScannable(name) {
			continue
		}
		if dir == "" {
			if dir, err = attachmentDir(); err != nil {
				warn(fmt.Errorf("attachments: %w", err))
				return nil, ""
			}
		}
		pr, pw := io.Pipe()
		go func() {
			_, werr := a.WriteTo(pw)
			pw.CloseWithError(werr)
		}()
		att, serr := saveAttachment(dir, index, name, pr)
		pr.Close()
		if serr != nil {
			warn(fmt.Errorf("attachment %q: %w", name, serr))
			continue
		}
		out = append(out, att)
	}
	if err := it.Err(); err != nil {
		warn(fmt.Errorf("attachments: %w", err))
	}
	return out, dir
}

// itemText flattens one store item to its subject, sender, date, and
// scannable text. Contacts, appointments, and tasks matter as much as mail
// here — contact cards are dense PII — so unhandled property types fall
// back to their field dump rather than being dropped.
func itemText(m *pst.Message) (subject, from string, date time.Time, text string) {
	var b strings.Builder
	line := func(label, v string) {
		if v != "" {
			b.WriteString(label)
			b.WriteString(v)
			b.WriteString("\n")
		}
	}
	switch p := m.Properties.(type) {
	case *properties.Message:
		subject = p.GetSubject()
		from = p.GetFrom()
		// go-pst hands times over as Unix nanoseconds; delivery time for
		// received mail, submit time for sent.
		if ns := p.GetMessageDeliveryTime(); ns != 0 {
			date = time.Unix(0, ns)
		} else if ns := p.GetClientSubmitTime(); ns != 0 {
			date = time.Unix(0, ns)
		}
		line("Subject: ", subject)
		line("From: ", from)
		line("To: ", p.GetDisplayTo())
		line("Cc: ", p.GetDisplayCc())
		line("Bcc: ", p.GetDisplayBcc())
		body := p.GetBody()
		if body == "" {
			// No plain-text body: scan the HTML source as-is. Detectors
			// match digit/word patterns fine through markup.
			body = p.GetBodyHtml()
		}
		b.WriteString(body)
	case *properties.Contact:
		subject = p.GetEmail1DisplayName()
		b.WriteString(p.String())
	case *properties.Appointment:
		b.WriteString(p.String())
	case *properties.Task:
		b.WriteString(p.String())
	case *properties.Note:
		b.WriteString(p.String())
	case *properties.AddressBook:
		b.WriteString(p.String())
	default:
		return "", "", time.Time{}, ""
	}
	return subject, from, date, strings.TrimSpace(b.String())
}
