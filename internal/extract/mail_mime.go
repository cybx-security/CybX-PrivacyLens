package extract

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
)

// maxMessageBytes bounds how much of one message file is read: a message
// is text plus inline images; anything beyond this is attachment bulk.
const maxMessageBytes = 64 << 20

// readMessageSource reads one Outlook for Mac message file: the raw MIME
// message as received from the server. Headers and every text part (plain
// and HTML) become the item's text; attachments are skipped — only their
// names are kept — since their contents are binary payloads this scanner
// would need to extract by type. A message the MIME parser cannot make
// sense of is scanned as raw text rather than dropped: PII in a malformed
// message is still PII.
func readMessageSource(path string) ([]MailItem, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxMessageBytes))
	if err != nil {
		return nil, err
	}
	subject, text, perr := mimeText(raw)
	if text == "" {
		return nil, perr
	}
	return []MailItem{{
		Folder: outlookMacFolder(path), Subject: subject, Index: 1, Text: text,
	}}, perr
}

// mimeText flattens a MIME message to subject plus scannable text. The
// error reports a parse problem the caller may want to note; text is still
// returned alongside it whenever anything was readable.
func mimeText(raw []byte) (subject, text string, err error) {
	// go-message parses attacker-controllable input; a crash must degrade
	// to the raw-text fallback, never take down the scan.
	defer func() {
		if r := recover(); r != nil {
			subject, text = rawMessageText(raw)
			err = fmt.Errorf("mail parser crashed: %v", r)
		}
	}()
	mr, rerr := mail.CreateReader(bytes.NewReader(raw))
	if rerr != nil && !message.IsUnknownCharset(rerr) && !message.IsUnknownEncoding(rerr) || mr == nil {
		subject, text = rawMessageText(raw)
		return subject, text, fmt.Errorf("not readable as a mail message (scanned as raw text): %w", rerr)
	}
	var b strings.Builder
	line := func(label, v string) {
		if v = strings.TrimSpace(v); v != "" {
			b.WriteString(label)
			b.WriteString(v)
			b.WriteString("\n")
		}
	}
	h := mr.Header
	subject, _ = h.Subject()
	line("Subject: ", subject)
	for _, name := range []string{"From", "To", "Cc", "Bcc", "Reply-To"} {
		line(name+": ", headerText(h, name))
	}
	var firstErr error
	gotBody := false
	for {
		p, perr := mr.NextPart()
		if perr == io.EOF {
			break
		}
		if perr != nil {
			if message.IsUnknownCharset(perr) || message.IsUnknownEncoding(perr) {
				// The part is still delivered, undecoded; scan what it has.
				if p == nil {
					continue
				}
			} else {
				if firstErr == nil {
					firstErr = perr
				}
				break
			}
		}
		switch ph := p.Header.(type) {
		case *mail.InlineHeader:
			ct, _, _ := ph.ContentType()
			if ct == "" || strings.HasPrefix(ct, "text/") || strings.HasPrefix(ct, "message/") {
				body, _ := io.ReadAll(io.LimitReader(p.Body, maxMessageBytes))
				if len(bytes.TrimSpace(body)) > 0 {
					gotBody = true
				}
				b.WriteString("\n")
				b.Write(body)
				b.WriteString("\n")
			}
		case *mail.AttachmentHeader:
			name, _ := ph.Filename()
			line("Attachment: ", name)
			io.Copy(io.Discard, p.Body)
		}
	}
	text = strings.TrimSpace(b.String())
	if !gotBody {
		// Headers parsed but no body came out — a broken multipart
		// boundary, usually. Scan the whole file as text instead so the
		// body's PII is not lost behind a header-only item.
		rawSubject, rawText := rawMessageText(raw)
		if subject == "" {
			subject = rawSubject
		}
		text = rawText
	}
	return subject, text, firstErr
}

// headerText returns an address header as readable text: the parsed
// addresses when they parse, else the raw header, so a malformed address
// line is still scanned.
func headerText(h mail.Header, name string) string {
	addrs, err := h.AddressList(name)
	if err != nil || len(addrs) == 0 {
		return h.Get(name)
	}
	parts := make([]string, 0, len(addrs))
	for _, a := range addrs {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ", ")
}

var subjectLine = regexp.MustCompile(`(?mi)^Subject:[ \t]*(.*)$`)

// rawMessageText is the fallback for a message the MIME parser rejects:
// the whole file as text, with the subject lifted by a plain header match.
func rawMessageText(raw []byte) (subject, text string) {
	if m := subjectLine.FindSubmatch(raw); m != nil {
		subject = strings.TrimSpace(string(m[1]))
	}
	return subject, strings.TrimSpace(string(raw))
}
