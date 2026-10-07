package extract

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	netmail "net/mail"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/mail"
)

// maxMessageBytes bounds how much of one message file is read: a message
// is text plus inline images; anything beyond this is attachment bulk.
const maxMessageBytes = 64 << 20

// walkMessageSource reads one Outlook for Mac message file — the raw MIME
// message as received from the server — and delivers it to fn. Headers
// and every text part (plain and HTML) become the item's text; attachments
// are decoded to temporary files for fn to scan. A message the MIME parser
// cannot make sense of is scanned as raw text rather than dropped: PII in
// a malformed message is still PII.
func walkMessageSource(path string, fn func(MailItem)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxMessageBytes))
	if err != nil {
		return err
	}
	dir, err := attachmentDir()
	if err != nil {
		return err
	}
	msg, perr := mimeText(raw, dir)
	if msg.Text == "" {
		os.RemoveAll(dir)
		return perr
	}
	msg.Folder = outlookMacFolder(path)
	msg.Index = 1
	deliver(fn, msg, dir)
	return perr
}

// mimeText flattens a MIME message to its subject, sender, date, and
// scannable text (Folder and Index are left for the caller), and decodes
// its scannable attachments into dir. The error reports a parse problem
// the caller may want to note; text is still returned alongside it
// whenever anything was readable.
func mimeText(raw []byte, dir string) (item MailItem, err error) {
	// go-message parses attacker-controllable input; a crash must degrade
	// to the raw-text fallback, never take down the scan.
	defer func() {
		if r := recover(); r != nil {
			item.Subject, item.Text = rawMessageText(raw)
			err = fmt.Errorf("mail parser crashed: %v", r)
		}
	}()
	mr, rerr := mail.CreateReader(bytes.NewReader(raw))
	if rerr != nil && !message.IsUnknownCharset(rerr) && !message.IsUnknownEncoding(rerr) || mr == nil {
		item.Subject, item.Text = rawMessageText(raw)
		rh := rawHeaders(raw)
		item.From, item.Date = rh.get("From"), rh.date()
		return item, fmt.Errorf("not readable as a mail message (scanned as raw text): %w", rerr)
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
	item.Subject, _ = h.Subject()
	item.From = headerText(h, "From")
	if d, derr := h.Date(); derr == nil {
		item.Date = d
	}
	// Belt and braces: Outlook folds long or encoded subjects onto a
	// continuation line and uses legacy charsets; if the library came up
	// empty, read the raw header block ourselves.
	if item.Subject == "" || item.From == "" || item.Date.IsZero() {
		rh := rawHeaders(raw)
		if item.Subject == "" {
			item.Subject = rh.get("Subject")
		}
		if item.From == "" {
			item.From = rh.get("From")
		}
		if item.Date.IsZero() {
			item.Date = rh.date()
		}
	}
	line("Subject: ", item.Subject)
	for _, name := range []string{"From", "To", "Cc", "Bcc", "Reply-To"} {
		line(name+": ", headerText(h, name))
	}
	var firstErr error
	gotBody := false
	attIndex := 0
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
			attIndex++
			if name != "" && attachmentScannable(name) && dir != "" {
				att, aerr := saveAttachment(dir, attIndex, name, p.Body)
				if aerr != nil {
					if firstErr == nil {
						firstErr = fmt.Errorf("attachment %q: %w", name, aerr)
					}
				} else {
					item.Attachments = append(item.Attachments, att)
				}
			}
			io.Copy(io.Discard, p.Body)
		}
	}
	item.Text = strings.TrimSpace(b.String())
	if !gotBody {
		// Headers parsed but no body came out — a broken multipart
		// boundary, usually. Scan the whole file as text instead so the
		// body's PII is not lost behind a header-only item.
		rawSubject, rawText := rawMessageText(raw)
		if item.Subject == "" {
			item.Subject = rawSubject
		}
		item.Text = rawText
	}
	return item, firstErr
}

// rawHeader is a tolerant reading of a message's header block: lines up
// to the first blank line, continuation lines unfolded, names
// case-insensitive, RFC 2047 encoded words decoded where possible. It is
// what the subject, sender, and date fall back to when the MIME parser
// cannot deliver them.
type rawHeader map[string]string

func rawHeaders(raw []byte) rawHeader {
	out := rawHeader{}
	// Headers are 7-bit ASCII by specification; limit how far a headerless
	// blob is scanned.
	if len(raw) > 256<<10 {
		raw = raw[:256<<10]
	}
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	name := ""
	for _, l := range lines {
		if l == "" {
			break
		}
		if l[0] == ' ' || l[0] == '\t' {
			if name != "" {
				out[name] += " " + strings.TrimSpace(l)
			}
			continue
		}
		colon := strings.IndexByte(l, ':')
		if colon <= 0 || strings.ContainsAny(l[:colon], " \t") {
			// Not a header line: the block has ended (or never started).
			break
		}
		name = strings.ToLower(l[:colon])
		if _, dup := out[name]; !dup {
			out[name] = strings.TrimSpace(l[colon+1:])
		}
	}
	return out
}

// get returns a header decoded for display ("" when absent).
func (h rawHeader) get(name string) string {
	v := h[strings.ToLower(name)]
	if v == "" {
		return ""
	}
	dec := mime.WordDecoder{CharsetReader: charset.Reader}
	if d, err := dec.DecodeHeader(v); err == nil {
		return strings.TrimSpace(d)
	}
	return v
}

// date parses the Date header, tolerating the common deviations.
func (h rawHeader) date() time.Time {
	v := h["date"]
	if v == "" {
		return time.Time{}
	}
	if t, err := netmail.ParseDate(v); err == nil {
		return t
	}
	for _, layout := range []string{time.RFC1123Z, time.RFC1123, time.RFC822Z, time.RFC822, "2 Jan 2006 15:04:05 -0700", "Mon, 2 Jan 2006 15:04:05 MST"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t
		}
	}
	return time.Time{}
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

// rawMessageText is the fallback for a message the MIME parser rejects:
// the whole file as text, with the subject read from the raw header block.
func rawMessageText(raw []byte) (subject, text string) {
	return rawHeaders(raw).get("Subject"), strings.TrimSpace(string(raw))
}
