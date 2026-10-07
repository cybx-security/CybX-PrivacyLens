package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/rdataback/privacylens/internal/buildinfo"
	"github.com/rdataback/privacylens/internal/update"
)

// runUpdate installs the newest GitHub release (privacylens update).
// Exit codes: 0 up to date or updated, 1 an update is available (-check),
// 2 error.
func runUpdate(args []string) int {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	check := fs.Bool("check", false, "only report whether a newer version exists (exit code 1 if so)")
	yes := fs.Bool("yes", false, "install without asking")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n  privacylens update [-check] [-yes]\n\nChecks github.com/%s for a newer release and installs it (needs administrator rights).\n\nFlags:\n", buildinfo.UpdateRepo)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	rel, newer, err := update.Check(ctx, buildinfo.UpdateRepo, version)
	if err != nil && !errors.Is(err, update.ErrNoAsset) {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	fmt.Printf("%s v%s installed; newest release is v%s (%s)\n", toolName, version, rel.Version, rel.PublishedAt.Format("Jan 2, 2006"))
	if !newer {
		fmt.Println("You have the latest version.")
		return exitClean
	}
	if errors.Is(err, update.ErrNoAsset) {
		fmt.Fprintf(os.Stderr, "error: release v%s has no installer for %s/%s; see %s\n", rel.Version, runtime.GOOS, runtime.GOARCH, rel.URL)
		return exitError
	}
	if notes := strings.TrimSpace(rel.Notes); notes != "" {
		fmt.Printf("\nWhat's new:\n%s\n\n", indent(notes))
	}
	if *check {
		fmt.Printf("Update available: run \"privacylens update\" (as administrator) to install it.\n")
		return exitFindings
	}
	if !update.Elevated() {
		if runtime.GOOS == "windows" {
			fmt.Fprintln(os.Stderr, "error: updating needs administrator rights — run this from an elevated (Run as administrator) prompt")
		} else {
			fmt.Fprintln(os.Stderr, "error: updating needs administrator rights — run: sudo privacylens update")
		}
		return exitError
	}
	if !*yes {
		fmt.Printf("Install v%s now? [y/N] ", rel.Version)
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if l := strings.ToLower(strings.TrimSpace(line)); l != "y" && l != "yes" {
			fmt.Println("Not installed.")
			return exitClean
		}
	}
	dir, err := os.MkdirTemp("", "privacylens-update-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	fmt.Printf("Downloading %s…", rel.Asset.Name)
	lastPct := -1
	path, err := update.Download(ctx, rel, dir, func(done, total int64) {
		if total > 0 {
			if pct := int(done * 100 / total); pct/10 != lastPct/10 {
				lastPct = pct
				fmt.Printf(" %d%%", pct)
			}
		}
	})
	fmt.Println()
	if err != nil {
		os.RemoveAll(dir)
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	fmt.Println("Checksum verified. Installing…")
	err = update.Install(ctx, path, false)
	if errors.Is(err, update.ErrManual) {
		fmt.Printf("Downloaded to %s. Finish the update with:\n\n  %s\n", path, update.ManualSteps(path))
		return exitClean
	}
	os.RemoveAll(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	fmt.Printf("Updated to v%s. Scan settings, saved reports, and the weekly scan are unchanged.\n", rel.Version)
	return exitClean
}

func indent(s string) string {
	return "  " + strings.ReplaceAll(s, "\n", "\n  ")
}
