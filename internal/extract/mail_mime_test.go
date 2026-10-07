package extract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleMIME = "From: HR <hr@example.com>\r\n" +
	"To: Jane Doe <jane@example.com>\r\n" +
	"Subject: =?utf-8?q?Onboarding_=E2=80=94_forms?=\r\n" +
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
