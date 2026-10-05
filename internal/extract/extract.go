// Package extract pulls scannable plain text out of files: native text
// formats, Office Open XML documents (docx/xlsx/pptx), and PDFs.
package extract

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	xunicode "golang.org/x/text/encoding/unicode"
)

// Status classifies what FromFile could do with a file.
type Status int

const (
	// StatusOK means text was extracted and should be scanned.
	StatusOK Status = iota
	// StatusUnsupported means the file is binary or an unrecognized format.
	StatusUnsupported
	// StatusNeedsOCR means the file is a document (currently: PDF) that
	// opened fine but has no embedded text layer — a scan/image-only
	// document that OCR would be required to read.
	StatusNeedsOCR
	// StatusOCR means text was extracted via OCR and should be scanned.
	// Kept distinct from StatusOK so findings can be tagged as OCR-sourced
	// (OCR misreads characters; consumers may weight these differently).
	StatusOCR
)

// imageExts are raster formats OCR can read directly (when enabled).
var imageExts = map[string]bool{
	".jpg": true, ".jpeg": true, ".png": true, ".tif": true, ".tiff": true,
	".bmp": true,
}

// textExts are extensions always treated as plain text.
var textExts = map[string]bool{
	".txt": true, ".text": true, ".csv": true, ".tsv": true, ".log": true,
	".md": true, ".markdown": true, ".json": true, ".xml": true, ".yaml": true,
	".yml": true, ".html": true, ".htm": true, ".ini": true, ".cfg": true,
	".conf": true, ".toml": true, ".sql": true, ".rtf": true, ".eml": true,
	".vcf": true, ".ics": true, ".env": true, ".properties": true,
}

// skipExts are extensions known to be binary and never worth sniffing.
var skipExts = map[string]bool{
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true,
	".tiff": true, ".webp": true, ".heic": true, ".ico": true, ".svgz": true,
	".mp3": true, ".mp4": true, ".mov": true, ".avi": true, ".mkv": true,
	".wav": true, ".flac": true, ".zip": true, ".gz": true, ".tar": true,
	".bz2": true, ".xz": true, ".7z": true, ".rar": true, ".dmg": true,
	".iso": true, ".exe": true, ".dll": true, ".so": true, ".dylib": true,
	".bin": true, ".dat": true, ".db": true, ".sqlite": true, ".class": true,
	".pyc": true, ".o": true, ".a": true, ".woff": true, ".woff2": true,
	".ttf": true, ".otf": true, ".doc": true, ".xls": true, ".ppt": true,
}

// FromFile extracts text from path. The Status tells the caller whether the
// text should be scanned, the file skipped, or the file flagged as needing
// OCR (a document with no text layer).
func FromFile(path string) (text string, status Status, err error) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".docx":
		text, err = docxText(path)
		return text, StatusOK, err
	case ".xlsx", ".xlsm":
		text, err = xlsxText(path)
		return text, StatusOK, err
	case ".pptx":
		text, err = pptxText(path)
		return text, StatusOK, err
	case ".pdf":
		text, err = pdfText(path)
		if err != nil {
			return "", StatusOK, err
		}
		if lacksTextLayer(text) {
			if imgOK, pdfOK := ocrReady(); imgOK && pdfOK {
				t, oerr := ocrPDF(path)
				if oerr != nil {
					return "", StatusOK, oerr
				}
				return t, StatusOCR, nil
			}
			return "", StatusNeedsOCR, nil
		}
		return text, StatusOK, nil
	}
	if imageExts[ext] {
		// Images are skipped entirely unless OCR is on; with OCR on but
		// tesseract missing they're flagged needs_ocr so the coverage gap
		// is visible.
		if !ocrEnabled {
			return "", StatusUnsupported, nil
		}
		if imgOK, _ := ocrReady(); !imgOK {
			return "", StatusNeedsOCR, nil
		}
		text, err := ocrImage(path)
		if err != nil {
			return "", StatusOK, err
		}
		return text, StatusOCR, nil
	}
	if skipExts[ext] {
		return "", StatusUnsupported, nil
	}
	if textExts[ext] {
		b, err := os.ReadFile(path)
		return decodeText(b), StatusOK, err
	}
	// Unknown extension: sniff the first chunk and scan it only if it looks
	// like text (source code, extension-less config files, etc). Read just
	// the probe first — most unknown-extension files are binary, and reading
	// a whole 50MB blob only to reject it from its first 8KB is the
	// difference between a directory walk and a full disk read.
	f, err := os.Open(path)
	if err != nil {
		return "", StatusOK, err
	}
	defer f.Close()
	probe := make([]byte, 8192)
	n, err := io.ReadFull(f, probe)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return "", StatusOK, err
	}
	probe = probe[:n]
	// UTF-16 is full of NUL bytes, so judge it by its decoded form — the
	// raw-byte test below would write every UTF-16 file off as binary.
	sniff := probe
	if _, isUTF16 := utf16Order(probe); isUTF16 {
		sniff = []byte(decodeText(probe))
	}
	if !looksLikeText(sniff) {
		return "", StatusUnsupported, nil
	}
	rest, err := io.ReadAll(f)
	if err != nil {
		return "", StatusOK, err
	}
	return decodeText(append(probe, rest...)), StatusOK, nil
}

// decodeText converts a text file's bytes to a scannable string. UTF-16 —
// what Windows PowerShell's `>` redirection, Notepad's "Unicode" encoding,
// and many database/registry exports write — is transcoded to UTF-8: read
// as-is, the NUL byte between every character keeps every detector from
// matching, so the file would count as scanned while nothing in it could
// ever be found. Everything else (UTF-8, ASCII, legacy single-byte code
// pages) is returned unchanged; the detectors match ASCII patterns, which
// those encodings all share.
func decodeText(b []byte) string {
	bigEndian, ok := utf16Order(b)
	if !ok {
		return string(b)
	}
	order := xunicode.LittleEndian
	if bigEndian {
		order = xunicode.BigEndian
	}
	// UseBOM consumes a leading byte-order mark when present and falls back
	// to the sniffed order when not. Invalid sequences decode to U+FFFD.
	out, err := xunicode.UTF16(order, xunicode.UseBOM).NewDecoder().Bytes(b)
	if err != nil {
		return string(b)
	}
	return string(out)
}

// utf16Order reports whether b is UTF-16 text and, if so, its byte order.
// A byte-order mark settles it. Without one, mostly-Latin UTF-16 is still
// unmistakable: one byte of nearly every pair is NUL (the high byte), and
// the other almost never is.
func utf16Order(b []byte) (bigEndian, ok bool) {
	switch {
	case bytes.HasPrefix(b, []byte{0xFF, 0xFE}):
		return false, true
	case bytes.HasPrefix(b, []byte{0xFE, 0xFF}):
		return true, true
	}
	if len(b) > 8192 {
		b = b[:8192]
	}
	pairs := len(b) / 2
	if pairs < 8 {
		return false, false
	}
	var nulEven, nulOdd int
	for i := 0; i+1 < len(b); i += 2 {
		if b[i] == 0 {
			nulEven++
		}
		if b[i+1] == 0 {
			nulOdd++
		}
	}
	switch {
	case nulOdd*10 >= pairs*8 && nulEven*20 <= pairs:
		return false, true // little-endian: NUL high bytes at odd offsets
	case nulEven*10 >= pairs*8 && nulOdd*20 <= pairs:
		return true, true
	}
	return false, false
}

// lacksTextLayer reports whether extracted document text is so sparse that
// the document is almost certainly a scan/image with no embedded text —
// fewer than 20 visible characters across the whole document.
func lacksTextLayer(text string) bool {
	visible := 0
	for _, r := range text {
		if !unicode.IsSpace(r) {
			visible++
			if visible >= 20 {
				return false
			}
		}
	}
	return true
}

// looksLikeText reports whether b appears to be textual: no NUL bytes and a
// low proportion of non-printable control characters.
func looksLikeText(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	control := 0
	for _, c := range b {
		if c == 0 {
			return false
		}
		if c < 32 && c != '\n' && c != '\r' && c != '\t' && c != '\f' {
			control++
		}
	}
	return control*100/len(b) < 5
}
