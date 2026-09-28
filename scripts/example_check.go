// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build ignore

// example_check compiles every program under examples/ so a README that
// points at them cannot point at something that no longer builds.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	files, err := filepath.Glob("examples/*.go")
	if err != nil || len(files) == 0 {
		fmt.Fprintln(os.Stderr, "example_check: no examples found")
		os.Exit(1)
	}
	for _, f := range files {
		cmd := exec.Command("go", "vet", f)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "example_check: %s does not compile\n", f)
			os.Exit(1)
		}
		fmt.Println("ok  ", f)
	}
}
