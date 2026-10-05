package extract

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// OCR is optional and runs through external tools invoked per file:
// tesseract for the OCR itself, and pdftoppm (poppler) to rasterize the
// pages of image-only PDFs first. Keeping the tools external preserves the
// pure-Go, CGo-free build and its trivial cross-compiles; when a tool is
// missing, affected files stay flagged needs_ocr exactly as before, so
// coverage gaps remain visible instead of silently ignored.

var ocrEnabled bool

// SetOCR turns OCR for image files and image-only PDFs on or off (the -ocr
// flag; the GUI sets it per scan). Extraction still degrades to needs_ocr
// when the tools are absent; call HaveOCR to warn the user up front. Not
// safe to flip while a scan is running.
func SetOCR(enabled bool) { ocrEnabled = enabled }

// HaveOCR reports what OCR can run right now: images need tesseract, PDFs
// additionally need pdftoppm to rasterize pages.
func HaveOCR() (images, pdfs bool) {
	return tesseractBin() != "", tesseractBin() != "" && pdftoppmBin() != ""
}

// RefreshOCRTools clears the cached tool lookups so the next HaveOCR call
// re-resolves them. The installer calls this after installing the tools —
// without it, the "not found" result cached before installation would
// stick for the life of the process.
func RefreshOCRTools() {
	tesseractOnce, pdftoppmOnce = sync.Once{}, sync.Once{}
	tesseractPath, pdftoppmPath = "", ""
}

// ocrReady is HaveOCR gated on OCR being enabled at all.
func ocrReady() (images, pdfs bool) {
	if !ocrEnabled {
		return false, false
	}
	return HaveOCR()
}

// ocrSem caps concurrent OCR jobs (a whole PDF counts as one job): OCR is
// CPU-heavy — seconds per page — and must not multiply by NumCPU workers.
var ocrSem = make(chan struct{}, 2)

const (
	// ocrPageTimeout bounds one tesseract invocation (one image or page).
	ocrPageTimeout = 2 * time.Minute
	// ocrRasterTimeout bounds rasterizing one PDF's pages.
	ocrRasterTimeout = 5 * time.Minute
	// ocrMaxPages caps how many pages of a single PDF are rasterized and
	// OCR'd, bounding worst-case cost per file (a 500-page scan would
	// otherwise monopolize the scan for an hour). The cap is surfaced: the
	// extracted text ends with a marker naming how many pages were read.
	ocrMaxPages = 50
)

var (
	tesseractOnce sync.Once
	tesseractPath string
	pdftoppmOnce  sync.Once
	pdftoppmPath  string
)

// tesseractBin locates tesseract: PRIVACYLENS_TESSERACT override, PATH,
// then the stock Windows install locations. Empty string = not available.
func tesseractBin() string {
	tesseractOnce.Do(func() {
		if p := os.Getenv("PRIVACYLENS_TESSERACT"); p != "" {
			tesseractPath = p
			return
		}
		if p, err := exec.LookPath("tesseract"); err == nil {
			tesseractPath = p
			return
		}
		if runtime.GOOS == "windows" {
			for _, p := range []string{
				`C:\Program Files\Tesseract-OCR\tesseract.exe`,
				`C:\Program Files (x86)\Tesseract-OCR\tesseract.exe`,
			} {
				if _, err := os.Stat(p); err == nil {
					tesseractPath = p
					return
				}
			}
		}
	})
	return tesseractPath
}

// pdftoppmBin locates poppler's pdftoppm: PRIVACYLENS_PDFTOPPM override,
// PATH, then (on Windows) the layouts poppler zip releases unpack to under
// Program Files — poppler zips aren't installers, so nothing puts them on
// PATH. Empty string = not available.
func pdftoppmBin() string {
	pdftoppmOnce.Do(func() {
		if p := os.Getenv("PRIVACYLENS_PDFTOPPM"); p != "" {
			pdftoppmPath = p
			return
		}
		if p, err := exec.LookPath("pdftoppm"); err == nil {
			pdftoppmPath = p
			return
		}
		if runtime.GOOS == "windows" {
			// "poppler*" also catches versioned sibling installs like
			// C:\Program Files\poppler-24.08.0.
			var dirs []string
			for _, base := range []string{`C:\Program Files\poppler`, `C:\Program Files (x86)\poppler`, `C:\poppler`} {
				hits, _ := filepath.Glob(base + "*")
				dirs = append(dirs, hits...)
			}
			pdftoppmPath = findExecUnder(dirs, "pdftoppm.exe")
		}
	})
	return pdftoppmPath
}

// findExecUnder searches each dir recursively (depth-capped) for exeName
// and returns the lexically-highest hit so the newest versioned folder
// wins, or "" if none. Poppler zip releases unpack to varying depths —
// poppler-X\Library\bin, or one level deeper when Windows Explorer's
// "Extract All" wraps everything in a folder named after the zip — so a
// fixed set of glob patterns kept missing real installs.
func findExecUnder(dirs []string, exeName string) string {
	const maxDepth = 6
	var hits []string
	for _, dir := range dirs {
		root := dir
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			rel, rerr := filepath.Rel(root, p)
			if rerr != nil {
				return fs.SkipDir
			}
			if d.IsDir() {
				if strings.Count(rel, string(filepath.Separator)) >= maxDepth {
					return fs.SkipDir
				}
				return nil
			}
			if strings.EqualFold(d.Name(), exeName) {
				hits = append(hits, p)
			}
			return nil
		})
	}
	if len(hits) == 0 {
		return ""
	}
	sort.Strings(hits)
	return hits[len(hits)-1]
}

// ocrImage runs tesseract on one image file.
func ocrImage(path string) (string, error) {
	ocrSem <- struct{}{}
	defer func() { <-ocrSem }()
	return runTesseract(path)
}

// ocrPDF rasterizes an image-only PDF's pages and OCRs each, returning the
// page texts joined with form feeds. The whole PDF holds one OCR slot so a
// long document doesn't starve other files.
func ocrPDF(path string) (string, error) {
	ocrSem <- struct{}{}
	defer func() { <-ocrSem }()

	dir, err := os.MkdirTemp("", "privacylens-ocr-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	prefix := filepath.Join(dir, "page")

	ctx, cancel := context.WithTimeout(context.Background(), ocrRasterTimeout)
	defer cancel()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, pdftoppmBin(),
		"-r", "200", "-gray", "-png", "-l", strconv.Itoa(ocrMaxPages), path, prefix)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("pdf rasterization timed out after %s", ocrRasterTimeout)
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("pdf rasterization failed: %s", msg)
	}

	pages, err := filepath.Glob(prefix + "-*.png")
	if err != nil || len(pages) == 0 {
		return "", fmt.Errorf("pdf rasterization produced no pages")
	}
	// pdftoppm zero-pads page numbers only up to the document's own page
	// count, so sort numerically, not lexically (page-10 vs page-2).
	sort.Slice(pages, func(i, j int) bool { return pageNum(pages[i]) < pageNum(pages[j]) })

	// Pages are joined with a bare form feed: everything after the Nth
	// "\f" is page N+1, which is how the scanner attributes findings to
	// page numbers.
	var sb strings.Builder
	for i, p := range pages {
		text, err := runTesseract(p)
		if err != nil {
			return "", fmt.Errorf("page %d: %w", i+1, err)
		}
		if i > 0 {
			sb.WriteString("\f")
		}
		sb.WriteString(text)
	}
	if len(pages) == ocrMaxPages {
		fmt.Fprintf(&sb, "\f[PrivacyLens: OCR stopped at the %d-page cap; later pages were not read]\n", ocrMaxPages)
	}
	return sb.String(), nil
}

func pageNum(p string) int {
	base := strings.TrimSuffix(filepath.Base(p), ".png")
	if i := strings.LastIndexByte(base, '-'); i >= 0 {
		if n, err := strconv.Atoi(base[i+1:]); err == nil {
			return n
		}
	}
	return 0
}

// runTesseract OCRs one image to text via stdout. Callers hold ocrSem.
func runTesseract(img string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ocrPageTimeout)
	defer cancel()
	var out, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, tesseractBin(), img, "stdout")
	cmd.Stdout = &out
	cmd.Stderr = &stderr // tesseract logs page diagnostics here; keep off the console
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("ocr timed out after %s", ocrPageTimeout)
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("ocr failed: %s", msg)
	}
	return out.String(), nil
}
