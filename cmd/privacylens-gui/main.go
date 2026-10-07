// Command privacylens-gui is the double-click launcher for the PrivacyLens
// GUI: no console, no flags. It starts the local web interface on a random
// loopback port and opens the default browser. The Windows release is built
// with -ldflags -H=windowsgui so no console window appears; startup
// failures are shown in a native dialog instead (there is no terminal to
// print to).
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/rdataback/privacylens/internal/buildinfo"
	"github.com/rdataback/privacylens/internal/extract"
	"github.com/rdataback/privacylens/internal/gui"
)

func main() {
	// PDF extraction re-executes this same binary as a sandboxed child, so
	// the launcher must answer the child invocation exactly like the CLI.
	if len(os.Args) > 1 && os.Args[1] == extract.PDFChildArg {
		os.Exit(extract.RunPDFChild(os.Args[2:]))
	}
	extract.EnablePDFIsolation()

	err := gui.Run(gui.Options{
		Addr:        "127.0.0.1:0",
		OpenBrowser: true,
		Tool:        buildinfo.Tool,
		Version:     buildinfo.Version,
		UpdateRepo:  buildinfo.UpdateRepo,
		// No console means no Ctrl+C: stop on our own once every
		// PrivacyLens tab has been closed for a while.
		IdleExit: 15 * time.Minute,
	})
	if err != nil {
		alert(fmt.Sprintf("PrivacyLens could not start: %v", err))
		os.Exit(1)
	}
}
