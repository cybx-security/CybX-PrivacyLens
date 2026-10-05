package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// stderrIsTerminal reports whether stderr is an interactive console (as
// opposed to a pipe, file, or service context).
func stderrIsTerminal() bool {
	fi, err := os.Stderr.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// progressLine renders one self-overwriting status line on stderr during an
// interactive scan, so a long scan is visibly alive. Plain "\r" + space
// padding, no ANSI escapes — works in any console, including legacy Windows.
type progressLine struct {
	last  time.Time
	width int
}

// update is wired to scanner.Options.Progress. It runs on the scanner's
// collector goroutine (already serialized, no locking needed) and is
// throttled so terminal writes never slow the scan.
func (p *progressLine) update(done, total, findings int) {
	now := time.Now()
	if done != total && now.Sub(p.last) < 200*time.Millisecond {
		return
	}
	p.last = now
	line := fmt.Sprintf("scanning %d/%d files, %d findings", done, total, findings)
	// done == 0 means the discovery walk is still running: the total is
	// growing, nothing has been scanned yet.
	if done == 0 {
		line = fmt.Sprintf("finding files... %d so far", total)
	}
	if len(line) < p.width {
		line += strings.Repeat(" ", p.width-len(line))
	} else {
		p.width = len(line)
	}
	fmt.Fprintf(os.Stderr, "\r%s", line)
}

// clear erases the status line so the report (or an error) starts on a
// clean row.
func (p *progressLine) clear() {
	if p.width == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", p.width))
}
