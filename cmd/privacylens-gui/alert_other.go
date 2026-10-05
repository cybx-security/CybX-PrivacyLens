//go:build !windows && !darwin

package main

import (
	"fmt"
	"os"
)

func alert(msg string) {
	fmt.Fprintln(os.Stderr, msg)
}
