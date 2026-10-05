package extract

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeZip builds a minimal Office-format file (which is just a zip of XML
// parts) in dir and returns its path.
func writeZip(t *testing.T, dir, name string, parts map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for p, content := range parts {
		w, err := zw.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDocxExtraction(t *testing.T) {
	doc := `<?xml version="1.0"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>Employee SSN: </w:t></w:r><w:r><w:t>219-09-9999</w:t></w:r></w:p>
    <w:p><w:r><w:t>Second paragraph</w:t></w:r></w:p>
  </w:body>
</w:document>`
	path := writeZip(t, t.TempDir(), "test.docx", map[string]string{"word/document.xml": doc})

	text, status, err := FromFile(path)
	if err != nil || status != StatusOK {
		t.Fatalf("FromFile: status=%v err=%v", status, err)
	}
	// Runs within a paragraph must concatenate without separators so PII
	// split across formatting runs stays intact.
	if !strings.Contains(text, "Employee SSN: 219-09-9999") {
		t.Errorf("docx text missing joined runs: %q", text)
	}
	if !strings.Contains(text, "\nSecond paragraph") {
		t.Errorf("paragraphs should be newline-separated: %q", text)
	}
}

func TestXlsxExtraction(t *testing.T) {
	shared := `<?xml version="1.0"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <si><t>ssn</t></si><si><t>jane@example.com</t></si>
</sst>`
	sheet := `<?xml version="1.0"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row><c r="A1" t="s"><v>0</v></c><c r="B1"><v>219099999</v></c></row>
    <row><c r="A2" t="s"><v>1</v></c></row>
  </sheetData>
</worksheet>`
	path := writeZip(t, t.TempDir(), "test.xlsx", map[string]string{
		"xl/sharedStrings.xml":     shared,
		"xl/worksheets/sheet1.xml": sheet,
	})

	text, status, err := FromFile(path)
	if err != nil || status != StatusOK {
		t.Fatalf("FromFile: status=%v err=%v", status, err)
	}
	for _, want := range []string{"ssn", "jane@example.com", "219099999"} {
		if !strings.Contains(text, want) {
			t.Errorf("xlsx text missing %q: %q", want, text)
		}
	}
	// Shared-string cells store an index in <v>; those indices must not leak
	// into the text as fake numeric values (row A1 holds index 0).
	if strings.Contains(text, "\n0 ") {
		t.Errorf("shared-string index leaked into text: %q", text)
	}
}

func TestBinarySniffing(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "blob")
	if err := os.WriteFile(bin, []byte{0x7f, 'E', 'L', 'F', 0, 1, 2, 3}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, status, _ := FromFile(bin); status != StatusUnsupported {
		t.Error("binary file with NUL bytes should be unsupported")
	}

	txt := filepath.Join(dir, "notes") // no extension
	if err := os.WriteFile(txt, []byte("ssn 219-09-9999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	text, status, err := FromFile(txt)
	if err != nil || status != StatusOK || !strings.Contains(text, "219-09-9999") {
		t.Errorf("extension-less text file should be scanned: status=%v err=%v", status, err)
	}
}

// minimalBlankPDF writes a structurally valid one-page PDF with an empty
// content stream — the shape of a scanned/image-only document once its
// images are ignored.
func minimalBlankPDF(t *testing.T, dir string) string {
	t.Helper()
	var b []byte
	var offsets []int
	add := func(s string) {
		offsets = append(offsets, len(b))
		b = append(b, s...)
	}
	b = append(b, "%PDF-1.4\n"...)
	add("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
	add("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
	add("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << >> >>\nendobj\n")
	add("4 0 obj\n<< /Length 0 >>\nstream\n\nendstream\nendobj\n")
	xref := len(b)
	b = append(b, "xref\n0 5\n0000000000 65535 f \n"...)
	for _, off := range offsets {
		b = append(b, []byte(fmt.Sprintf("%010d 00000 n \n", off))...)
	}
	b = append(b, []byte(fmt.Sprintf("trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", xref))...)

	path := filepath.Join(dir, "scanned.pdf")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestImageOnlyPDFNeedsOCR(t *testing.T) {
	path := minimalBlankPDF(t, t.TempDir())
	_, status, err := FromFile(path)
	if err != nil {
		t.Fatalf("blank PDF should parse cleanly, got error: %v", err)
	}
	if status != StatusNeedsOCR {
		t.Errorf("PDF with no text layer should be StatusNeedsOCR, got %v", status)
	}
}

func TestLacksTextLayer(t *testing.T) {
	if !lacksTextLayer("") || !lacksTextLayer("  \n\t ") || !lacksTextLayer("p.1") {
		t.Error("empty/near-empty text should lack a text layer")
	}
	if lacksTextLayer("Employee SSN: 219-09-9999 on file") {
		t.Error("real sentence should not be classified as needing OCR")
	}
}

// utf16Bytes encodes ASCII s as UTF-16 in the given byte order, optionally
// led by a byte-order mark.
func utf16Bytes(s string, bigEndian, bom bool) []byte {
	var b []byte
	put := func(lo, hi byte) {
		if bigEndian {
			b = append(b, hi, lo)
		} else {
			b = append(b, lo, hi)
		}
	}
	if bom {
		put(0xFF, 0xFE)
	}
	for i := 0; i < len(s); i++ {
		put(s[i], 0)
	}
	return b
}

// UTF-16 text (PowerShell `>` output, Notepad "Unicode") must be decoded:
// scanned raw, the NUL between every character hides all of its PII while
// the file still counts as scanned.
func TestUTF16TextIsDecoded(t *testing.T) {
	const content = "Employee SSN: 219-09-9999\r\nemail: jane@example.com\r\n"
	dir := t.TempDir()
	cases := []struct {
		name           string
		bigEndian, bom bool
	}{
		{"le_bom.txt", false, true},
		{"be_bom.txt", true, true},
		{"le_nobom.csv", false, false},
		{"be_nobom.log", true, false},
		{"le_bom_noext", false, true},
		{"le_nobom_noext", false, false},
	}
	for _, c := range cases {
		path := filepath.Join(dir, c.name)
		if err := os.WriteFile(path, utf16Bytes(content, c.bigEndian, c.bom), 0o600); err != nil {
			t.Fatal(err)
		}
		text, status, err := FromFile(path)
		if err != nil || status != StatusOK {
			t.Errorf("%s: status=%v err=%v", c.name, status, err)
			continue
		}
		if text != content {
			t.Errorf("%s: decoded text = %q, want %q", c.name, text, content)
		}
	}
}

func TestDecodeTextEdgeCases(t *testing.T) {
	// A stray trailing byte must not make the decoder give up on the file.
	odd := append(utf16Bytes("SSN 219-09-9999 on file", false, true), 0x41)
	if got := decodeText(odd); !strings.Contains(got, "SSN 219-09-9999 on file") {
		t.Errorf("odd-length UTF-16 = %q", got)
	}
	// UTF-8 and plain ASCII pass through byte-for-byte.
	for _, s := range []string{"", "plain ascii 219-09-9999", "café résumé 日本語", "a\x00b"} {
		if got := decodeText([]byte(s)); got != s {
			t.Errorf("decodeText(%q) = %q, want unchanged", s, got)
		}
	}
}

// Binary files must still be rejected by the unknown-extension sniff even
// though UTF-16 (which is NUL-heavy) is now accepted.
func TestBinaryStillUnsupported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blob")
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i * 7)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, status, err := FromFile(path); err != nil || status != StatusUnsupported {
		t.Errorf("binary blob: status=%v err=%v, want StatusUnsupported", status, err)
	}
}

// A document whose text expands past the cap is an error for that one file,
// not an out-of-memory crash for the whole scan.
func TestOOXMLTextCap(t *testing.T) {
	old := maxOOXMLText
	maxOOXMLText = 1 << 10
	defer func() { maxOOXMLText = old }()

	big := strings.Repeat("A", 4<<10)
	doc := `<w:document xmlns:w="x"><w:body><w:p><w:r><w:t>` + big + `</w:t></w:r></w:p></w:body></w:document>`
	dir := t.TempDir()
	if _, _, err := FromFile(writeZip(t, dir, "bomb.docx", map[string]string{"word/document.xml": doc})); err == nil {
		t.Error("docx over the text cap: expected an error")
	}
	sheet := `<worksheet><sheetData><row><c><v>` + big + `</v></c></row></sheetData></worksheet>`
	if _, _, err := FromFile(writeZip(t, dir, "bomb.xlsx", map[string]string{"xl/worksheets/sheet1.xml": sheet})); err == nil {
		t.Error("xlsx over the text cap: expected an error")
	}
}
