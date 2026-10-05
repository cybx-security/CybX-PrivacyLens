package extract

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	pdflib "github.com/ledongthuc/pdf"
)

// PDFChildArg is the hidden argv[1] with which the privacylens binary
// re-invokes itself to extract a single PDF in an isolated child process.
const PDFChildArg = "__pdf-extract"

// pdfChildErrExit is the child's exit code for a clean extraction failure
// (malformed pdf), as opposed to an OOM abort or crash.
const pdfChildErrExit = 3

// pdfChildMemLimit is the GOMEMLIMIT given to the child. It is a soft limit:
// it makes the child's GC push back well before the machine's commit limit,
// but a truly unbounded allocation still kills the child — which is the
// point of the isolation.
const pdfChildMemLimit = "512MiB"

// pdfChildTimeout bounds how long one PDF may take to parse before the child
// is killed and the file reported as an error.
const pdfChildTimeout = 2 * time.Minute

// pdfIsolate is set by the privacylens binary (see EnablePDFIsolation); it
// stays false under `go test`, where os.Executable is the test binary and
// cannot serve as the extraction child.
var pdfIsolate bool

// EnablePDFIsolation makes pdfText run each extraction in a child process so
// a pathological PDF can only kill that process, not the whole scan. Only
// the privacylens main may call this: the running executable must implement
// the PDFChildArg mode.
func EnablePDFIsolation() { pdfIsolate = true }

// pdfSem caps concurrent PDF extractions. PDFs are the one format whose
// parse memory is not bounded by file size (compressed streams, object
// graphs), so scanning with NumCPU workers must not mean NumCPU PDFs
// in flight at once.
var pdfSem = make(chan struct{}, 2)

// pdfText extracts the embedded text layer of a PDF. Scanned/image-only PDFs
// yield little or no text (OCR is out of scope for now).
func pdfText(path string) (string, error) {
	pdfSem <- struct{}{}
	defer func() { <-pdfSem }()
	if !pdfIsolate {
		return PDFTextDirect(path)
	}
	return pdfTextChild(path)
}

// PDFTextDirect parses the PDF in-process. The library can panic on
// malformed files, so recover and surface that as an error; a runtime OOM,
// however, is a fatal error no recover can catch — that is what the child
// process in pdfTextChild exists to contain.
func PDFTextDirect(path string) (text string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("malformed pdf: %v", r)
		}
	}()

	f, r, err := pdflib.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	body, err := r.GetPlainText()
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	if _, err := io.Copy(&sb, body); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// pdfTextChild runs PDFTextDirect in a child process (this same executable
// invoked with PDFChildArg) so that an out-of-memory abort or hang on a
// pathological PDF costs one file, not the scan.
func pdfTextChild(path string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return PDFTextDirect(path)
	}

	ctx, cancel := context.WithTimeout(context.Background(), pdfChildTimeout)
	defer cancel()

	var out, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, exe, PDFChildArg, path)
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	cmd.Env = append(os.Environ(), "GOMEMLIMIT="+pdfChildMemLimit)

	err = cmd.Run()
	if err == nil {
		return out.String(), nil
	}
	if ctx.Err() != nil {
		return "", fmt.Errorf("pdf extraction timed out after %s", pdfChildTimeout)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == pdfChildErrExit {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = "malformed pdf"
		}
		return "", fmt.Errorf("%s", msg)
	}
	return "", fmt.Errorf("pdf extraction crashed (likely out of memory on a malformed pdf): %v", err)
}

// RunPDFChild implements the hidden PDFChildArg mode: extract one PDF's text
// to stdout. It returns the process exit code — 0 with the text on stdout,
// or pdfChildErrExit with the reason on stderr.
func RunPDFChild(args []string) int {
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "usage: privacylens %s <file.pdf>\n", PDFChildArg)
		return pdfChildErrExit
	}
	text, err := PDFTextDirect(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return pdfChildErrExit
	}
	io.WriteString(os.Stdout, text)
	return 0
}
