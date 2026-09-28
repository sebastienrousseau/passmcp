// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Command controlsdoc writes docs/compliance/<framework>.md from each
// mapping in spec/controls, and with -check fails when a committed page
// differs from what the mapping generates.
//
// The mapping is the source; the page is its rendering. Editing the page
// by hand would let the manual promise a control the reports do not carry,
// which is the one mistake a compliance page must not make.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"satellion.com/passmcp/spec/controls"
)

func main() {
	os.Exit(cli(os.Args[1:], os.Stdout, os.Stderr))
}

// cli is main with its arguments and streams passed in, returning the
// exit code.
func cli(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("controlsdoc", flag.ContinueOnError)
	fs.SetOutput(stderr)
	check := fs.Bool("check", false, "fail if a committed page differs from the mapping")
	dir := fs.String("dir", "docs/compliance", "where the pages live")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	stale, err := run(*dir, *check)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "controlsdoc:", err)
		return 1
	}
	for _, p := range stale {
		_, _ = fmt.Fprintf(stderr, "controlsdoc: %s is stale; run make controls\n", p)
	}
	if len(stale) > 0 {
		return 1
	}
	if *check {
		_, _ = fmt.Fprintln(stdout, "controlsdoc: every compliance page matches its mapping")
	}
	return 0
}

// run renders every framework's page. With check it compares instead of
// writing, and returns the pages that differ.
func run(dir string, check bool) ([]string, error) {
	var stale []string
	for _, f := range controls.Frameworks {
		m, err := controls.Load(f)
		if err != nil {
			return nil, err
		}
		var b bytes.Buffer
		if err := m.Markdown(&b); err != nil {
			return nil, err
		}
		path := filepath.Join(dir, string(f)+".md")
		if check {
			have, err := os.ReadFile(path) // #nosec G304 -- a page in the repository's own docs directory
			if err != nil || !bytes.Equal(have, b.Bytes()) {
				stale = append(stale, path)
			}
			continue
		}
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
			return nil, err
		}
	}
	return stale, nil
}
