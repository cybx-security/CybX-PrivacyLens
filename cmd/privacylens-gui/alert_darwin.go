//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
)

// alert shows a native dialog: launched from an .app bundle there is no
// terminal for a startup failure to print to. Stderr is still written for
// the Terminal-launch case.
func alert(msg string) {
	script := fmt.Sprintf("display dialog %q buttons {\"OK\"} default button 1 with icon stop with title \"PrivacyLens\"", msg)
	exec.Command("osascript", "-e", script).Run()
	fmt.Fprintln(os.Stderr, msg)
}
