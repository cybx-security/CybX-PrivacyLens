package extract

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleMIME = "From: HR <hr@example.com>\r\n" +
	"To: Jane Doe <jane@example.com>\r\n" +
	"Subject: =?utf-8?q?Onboarding_=E2=80=94_forms?=\r\n" +
	"Date: Tue, 07 Oct 2026 09:15:00 -0400\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: multipart/mixed; boundary=\"b1\"\r\n" +
	"\r\n" +
	"--b1\r\n" +
	"Content-Type: multipart/alternative; boundary=\"b2\"\r\n" +
	"\r\n" +
	"--b2\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n" +
	"Content-Transfer-Encoding: quoted-printable\r\n" +
	"\r\n" +
	"Her SSN is 219-09-9999 =E2=80=94 please file it.\r\n" +
	"--b2\r\n" +
	"Content-Type: text/html; charset=utf-8\r\n" +
	"\r\n" +
	"<p>Card <b>4111 1111 1111 1111</b></p>\r\n" +
	"--b2--\r\n" +
	"--b1\r\n" +
	"Content-Type: application/pdf; name=\"w4.pdf\"\r\n" +
	"Content-Disposition: attachment; filename=\"w4.pdf\"\r\n" +
	"Content-Transfer-Encoding: base64\r\n" +
	"\r\n" +
	"JVBERi0xLjQKJcOkw7zDtsOfCjIgMCBvYmoKPDwvTGVuZ3RoIDMgMCBSL0ZpbHRlci9GbGF0ZURlY29kZT4+CnN0cmVhbQ==\r\n" +
	"--b1--\r\n"

func TestReadMessageSource(t *testing.T) {
	profile := filepath.Join(t.TempDir(), "Outlook 15 Profiles", "Main Profile", "Data", "Message Sources", "0", "3")
	if err := os.MkdirAll(profile, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(profile, "x_12.olk15MsgSource")
	if err := os.WriteFile(path, []byte(sampleMIME), 0o600); err != nil {
		t.Fatal(err)
	}
	if !IsMailStore(path) || !IsMessageSource(path) || IsMessageSource("a.pst") {
		t.Fatal("message-file detection by extension is wrong")
	}
	items, err := ReadMailStore(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("items = %d, want 1", len(items))
	}
	it := items[0]
	if it.Folder != "Outlook for Mac — Main Profile" || it.Subject != "Onboarding — forms" || it.Index != 1 {
		t.Errorf("item = %+v", it)
	}
	if it.From != "\"HR\" <hr@example.com>" || it.Date.IsZero() || it.Date.UTC().Format("2006-01-02 15:04") != "2026-10-07 13:15" {
		t.Errorf("from/date = %q / %v", it.From, it.Date)
	}
	for _, want := range []string{"Subject: Onboarding — forms", "hr@example.com", "jane@example.com", "SSN is 219-09-9999 —", "4111 1111 1111 1111", "Attachment: w4.pdf"} {
		if !strings.Contains(it.Text, want) {
			t.Errorf("text missing %q:\n%s", want, it.Text)
		}
	}
	if strings.Contains(it.Text, "JVBERi0x") {
		t.Error("attachment payload must not be scanned as text")
	}
	if got := MailStoreDisplayPath(path); !strings.HasSuffix(got, filepath.Join("Outlook 15 Profiles", "Main Profile")) {
		t.Errorf("display path = %q", got)
	}
}

// A file that is not valid MIME is still scanned, as raw text.
func TestReadMessageSourceMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.olk15MsgSource")
	raw := "Subject: receipt\nContent-Type: multipart/mixed; boundary=\"zz\n\nssn 219-09-9999 in a broken message"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	items, _ := ReadMailStore(path)
	if len(items) != 1 || !strings.Contains(items[0].Text, "219-09-9999") || items[0].Subject != "receipt" {
		t.Fatalf("items = %+v, want the raw text with its subject", items)
	}
	if items[0].Folder != "Outlook for Mac" {
		t.Errorf("folder = %q", items[0].Folder)
	}
}

// WalkMailStore hands attachments over as temporary files that exist only
// during the callback.
func TestWalkMessageSourceAttachments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.olk15MsgSource")
	if err := os.WriteFile(path, []byte(sampleMIME), 0o600); err != nil {
		t.Fatal(err)
	}
	var seen MailAttachment
	err := WalkMailStore(path, func(it MailItem) {
		if len(it.Attachments) != 1 {
			t.Fatalf("attachments = %+v, want the PDF", it.Attachments)
		}
		seen = it.Attachments[0]
		if seen.Name != "w4.pdf" || filepath.Ext(seen.Path) != ".pdf" || seen.Size == 0 {
			t.Errorf("attachment = %+v", seen)
		}
		if _, err := os.Stat(seen.Path); err != nil {
			t.Errorf("attachment file missing during callback: %v", err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(seen.Path); !os.IsNotExist(err) {
		t.Error("attachment temp file should be removed after the callback")
	}
	if !attachmentScannable("x.docx") || attachmentScannable("x.zip") || !attachmentScannable("scan.jpg") || !attachmentScannable("README") {
		t.Error("attachmentScannable has the wrong idea about types")
	}
}

// Outlook folds long or encoded subjects onto a continuation line. Both
// the MIME path and the raw fallback must still find them, with sender and
// date.
func TestFoldedEncodedSubject(t *testing.T) {
	folded := "From: Payroll <payroll@example.com>\r\n" +
		"Subject:\r\n =?utf-8?Q?Q3_payroll_=E2=80=94_SSN_list?=\r\n" +
		"Date: Tue, 07 Oct 2026 09:15:00 -0400\r\n"
	// Rejected by the parser: broken Content-Type parameter quoting.
	broken := folded + "Content-Type: multipart/mixed; boundary=\"zz\r\n\r\nssn 219-09-9999\r\n"
	// Accepted by the parser.
	fine := folded + "Content-Type: text/plain\r\n\r\nssn 219-09-9999\r\n"
	for name, raw := range map[string]string{"broken": broken, "fine": fine} {
		path := filepath.Join(t.TempDir(), name+".olk15MsgSource")
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		items, _ := ReadMailStore(path)
		if len(items) != 1 {
			t.Fatalf("%s: items = %+v", name, items)
		}
		it := items[0]
		if it.Subject != "Q3 payroll — SSN list" {
			t.Errorf("%s: subject = %q", name, it.Subject)
		}
		if !strings.Contains(it.From, "payroll@example.com") || it.Date.IsZero() {
			t.Errorf("%s: from/date = %q / %v", name, it.From, it.Date)
		}
		if !strings.Contains(it.Text, "219-09-9999") {
			t.Errorf("%s: body lost: %q", name, it.Text)
		}
	}
}

// Outlook for Mac writes a short binary preamble (with a "crSM" tag) in
// front of the raw message. It must be skipped, whether it ends mid-line
// or with a line break, and a plain message must pass through untouched.
func TestStripBinaryPrefix(t *testing.T) {
	msg := "Received: from mail.example.com\r\nFrom: HR <hr@example.com>\r\nSubject: Forms\r\nContent-Type: text/plain\r\n\r\nssn 219-09-9999\r\n"
	// The real layout, as recorded from a scan: 16 fixed bytes, a 16-byte
	// id (which may contain a newline or letters), crSM, 4 bytes, text.
	fixed := []byte{0xA0, 0x20, 0, 0, 1, 1, 1, 0, 2, 0, 0, 0, 3, 0, 0, 0}
	real := func(id, after []byte) []byte {
		b := append([]byte{}, fixed...)
		b = append(b, id...)
		b = append(b, 'c', 'r', 'S', 'M')
		return append(b, after...)
	}
	prefixes := map[string][]byte{
		"midline":      {0x00, 0x00, 0x01, 0x20, 'e', 0xC9, 0x9F, '}', '>', 'K', 0x8F, 0xFE, '.', 'x', 0xE9, 'M', 0x9A, 'c', 'r', 'S', 'M', 0x8E, '>', 0xBF},
		"linebreak":    {0x00, 0x00, 'd', 0xE2, 0xA0, ' ', 'p', 0xD2, 'C', 'c', 'r', 'S', 'M', 0xBF, '\n', 0xBF, ' ', '\n'},
		"real-letters": real([]byte{'d', 0xE2, 0xA0, ' ', 'p', 0xD2, 'C', 0xC2, 0xA9, 'Q', 'e', 0x0E, '&', 0x18, 0xC2, 0xA9}, []byte{0xBF, 0x05, 'w', 'L'}),
		"real-newline": real([]byte{'d', 0xE2, 0x1D, 0x08, 'E', 'D', 'E', '(', 0xC2, 0xA9, '\n', 0xC2, 0xA9, 'd', '2', 0x00}, []byte{0xBF, 0xBF, 'k', ';'}),
		"real-ctrl":    real([]byte{'e', 0xC9, 0x9F, 'R', '}', '>', 'K', 0xC2, 0xA9, 0xB6, 0x04, '.', 'x', 0xC2, 'M', 0x19}, []byte{0xBF, '>', 0x7F, 0xBF}),
		"none":         {},
	}
	for name, prefix := range prefixes {
		raw := append(append([]byte{}, prefix...), msg...)
		got := stripBinaryPrefix(raw)
		if string(got) != msg {
			t.Errorf("%s: prefix not stripped: %q", name, got[:min(len(got), 40)])
		}
		path := filepath.Join(t.TempDir(), name+".olk15MsgSource")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		items, err := ReadMailStore(path)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", name, err)
		}
		if len(items) != 1 || items[0].Subject != "Forms" || !strings.Contains(items[0].From, "hr@example.com") || !strings.Contains(items[0].Text, "219-09-9999") {
			t.Errorf("%s: items = %+v", name, items)
		}
	}
	// Pure binary with an accidental "ab: " in it is left alone.
	junk := []byte{0x01, 0x02, 'a', 'b', ':', ' ', 0x03, 0x04, '\n', 0x05}
	if got := stripBinaryPrefix(junk); !bytes.Equal(got, junk) {
		t.Errorf("binary without a header block was altered: %q", got)
	}
}
