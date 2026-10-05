package extract

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// enableOCRForTest turns OCR on and resets the cached tool lookups so each
// test resolves tools from its own environment; everything is restored on
// cleanup.
func enableOCRForTest(t *testing.T) {
	t.Helper()
	reset := func() {
		tesseractOnce, pdftoppmOnce = sync.Once{}, sync.Once{}
		tesseractPath, pdftoppmPath = "", ""
	}
	ocrEnabled = true
	reset()
	t.Cleanup(func() {
		ocrEnabled = false
		reset()
	})
}

// writeStub creates a fake executable shell script.
func writeStub(t *testing.T, path, script string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestImagesSkippedWithoutOCR(t *testing.T) {
	img := filepath.Join(t.TempDir(), "scan.png")
	if err := os.WriteFile(img, []byte("not-really-png"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, status, err := FromFile(img)
	if err != nil || status != StatusUnsupported {
		t.Errorf("image with OCR off should be StatusUnsupported, got %v err %v", status, err)
	}
}

func TestImagesFlaggedWhenTesseractMissing(t *testing.T) {
	enableOCRForTest(t)
	t.Setenv("PRIVACYLENS_TESSERACT", "")
	t.Setenv("PATH", t.TempDir()) // nothing in it
	img := filepath.Join(t.TempDir(), "scan.jpg")
	if err := os.WriteFile(img, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, status, err := FromFile(img)
	if err != nil || status != StatusNeedsOCR {
		t.Errorf("image with OCR on but no tesseract should be StatusNeedsOCR, got %v err %v", status, err)
	}
}

func TestOCRImageViaStub(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script stubs")
	}
	enableOCRForTest(t)
	dir := t.TempDir()
	stub := filepath.Join(dir, "tesseract")
	writeStub(t, stub, `echo "Patient SSN: 219-09-9999"`)
	t.Setenv("PRIVACYLENS_TESSERACT", stub)

	img := filepath.Join(dir, "scan.png")
	if err := os.WriteFile(img, []byte("fake image bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	text, status, err := FromFile(img)
	if err != nil {
		t.Fatal(err)
	}
	if status != StatusOCR {
		t.Errorf("want StatusOCR, got %v", status)
	}
	if !strings.Contains(text, "219-09-9999") {
		t.Errorf("OCR text missing: %q", text)
	}
}

func TestOCRPDFViaStubs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script stubs")
	}
	enableOCRForTest(t)
	dir := t.TempDir()
	// pdftoppm stub: writes one fake page image at <prefix>-1.png (the
	// prefix is the last argument).
	writeStub(t, filepath.Join(dir, "pdftoppm"), `for a in "$@"; do last="$a"; done
printf fake > "$last-1.png"
printf fake > "$last-2.png"`)
	writeStub(t, filepath.Join(dir, "tesseract"), `case "$1" in
*-1.png) echo "Scanned card 4111 1111 1111 1111" ;;
*-2.png) echo "Second page SSN 219-09-9999" ;;
esac`)
	t.Setenv("PRIVACYLENS_PDFTOPPM", filepath.Join(dir, "pdftoppm"))
	t.Setenv("PRIVACYLENS_TESSERACT", filepath.Join(dir, "tesseract"))

	pdf := minimalBlankPDF(t, dir) // valid PDF, no text layer
	text, status, err := FromFile(pdf)
	if err != nil {
		t.Fatal(err)
	}
	if status != StatusOCR {
		t.Errorf("image-only PDF with OCR tools should be StatusOCR, got %v", status)
	}
	if !strings.Contains(text, "4111 1111 1111 1111") {
		t.Errorf("page 1 OCR text missing: %q", text)
	}
	// Pages must be joined with a form feed so the scanner can attribute
	// findings to page numbers.
	ff := strings.IndexByte(text, '\f')
	if ff < 0 || !strings.Contains(text[ff:], "219-09-9999") {
		t.Errorf("page 2 must follow a form feed separator: %q", text)
	}
}

func TestOCRPDFFlaggedWhenRasterizerMissing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script stubs")
	}
	enableOCRForTest(t)
	dir := t.TempDir()
	writeStub(t, filepath.Join(dir, "tesseract"), `echo text`)
	t.Setenv("PRIVACYLENS_TESSERACT", filepath.Join(dir, "tesseract"))
	t.Setenv("PRIVACYLENS_PDFTOPPM", "")
	t.Setenv("PATH", dir)

	pdf := minimalBlankPDF(t, dir)
	_, status, err := FromFile(pdf)
	if err != nil || status != StatusNeedsOCR {
		t.Errorf("image-only PDF without pdftoppm should stay StatusNeedsOCR, got %v err %v", status, err)
	}
}

func TestPageNumSort(t *testing.T) {
	if pageNum("page-10.png") < pageNum("page-2.png") {
		t.Error("page numbers must sort numerically")
	}
}

// TestFindExecUnder covers the layouts poppler ends up in on real machines:
// flat bin dirs, the versioned folder inside the release zip, and the extra
// wrapper folder Windows Explorer's "Extract All" adds (which the old glob
// patterns missed, leaving pdftoppm undetected after a by-the-book manual
// install).
func TestFindExecUnder(t *testing.T) {
	place := func(t *testing.T, parts ...string) string {
		t.Helper()
		p := filepath.Join(parts...)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("flat and nested layouts", func(t *testing.T) {
		for _, layout := range [][]string{
			{"Library", "bin", "pdftoppm.exe"},
			{"bin", "pdftoppm.exe"},
			{"poppler-24.08.0", "Library", "bin", "pdftoppm.exe"},
			{"Release-26.02.0-0", "poppler-26.02.0", "Library", "bin", "pdftoppm.exe"},
		} {
			base := t.TempDir()
			want := place(t, append([]string{base}, layout...)...)
			if got := findExecUnder([]string{base}, "pdftoppm.exe"); got != want {
				t.Errorf("layout %v: got %q, want %q", layout, got, want)
			}
		}
	})

	t.Run("highest version wins", func(t *testing.T) {
		base := t.TempDir()
		place(t, base, "poppler-24.08.0", "Library", "bin", "pdftoppm.exe")
		want := place(t, base, "poppler-26.02.0", "Library", "bin", "pdftoppm.exe")
		if got := findExecUnder([]string{base}, "pdftoppm.exe"); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("case-insensitive name", func(t *testing.T) {
		base := t.TempDir()
		want := place(t, base, "bin", "PDFToPPM.EXE")
		if got := findExecUnder([]string{base}, "pdftoppm.exe"); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("missing and depth-capped", func(t *testing.T) {
		if got := findExecUnder([]string{filepath.Join(t.TempDir(), "nope")}, "pdftoppm.exe"); got != "" {
			t.Errorf("nonexistent dir: got %q, want empty", got)
		}
		base := t.TempDir()
		place(t, base, "a", "b", "c", "d", "e", "f", "g", "pdftoppm.exe")
		if got := findExecUnder([]string{base}, "pdftoppm.exe"); got != "" {
			t.Errorf("beyond depth cap: got %q, want empty", got)
		}
	})
}
