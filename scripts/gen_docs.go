// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build ignore

// gen_docs writes manpages and shell completions generated from the cobra
// command tree, so they can never disagree with --help.
//
//	go run ./scripts/gen_docs.go build
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra/doc"
	"satellion.com/passmcp/cmd"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gen_docs <output-dir>")
		os.Exit(2)
	}
	out := os.Args[1]
	man := filepath.Join(out, "man")
	comp := filepath.Join(out, "completions")
	for _, d := range []string{man, comp} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			fail(err)
		}
	}
	root := cmd.Root()
	root.DisableAutoGenTag = true
	date := manDate()
	if err := doc.GenManTree(root, &doc.GenManHeader{Title: "PASSMCP", Section: "1", Source: "passmcp " + cmd.Version, Manual: "passmcp manual", Date: &date}, man); err != nil {
		fail(err)
	}
	if err := tidyMan(man, date); err != nil {
		fail(err)
	}
	if err := root.GenBashCompletionFileV2(filepath.Join(comp, "passmcp.bash"), true); err != nil {
		fail(err)
	}
	if err := root.GenZshCompletionFile(filepath.Join(comp, "passmcp.zsh")); err != nil {
		fail(err)
	}
	if err := root.GenFishCompletionFile(filepath.Join(comp, "passmcp.fish"), true); err != nil {
		fail(err)
	}
	if err := root.GenPowerShellCompletionFileWithDesc(filepath.Join(comp, "passmcp.ps1")); err != nil {
		fail(err)
	}
	fmt.Printf("wrote manpages to %s and completions to %s\n", man, comp)
}

// manDate honours SOURCE_DATE_EPOCH so two builds of a commit produce
// identical pages.
func manDate() time.Time {
	if v := os.Getenv("SOURCE_DATE_EPOCH"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return time.Unix(n, 0).UTC()
		}
	}
	return time.Now().UTC()
}

// tidyMan rewrites what cobra/doc emits that mandoc -T lint rejects: the
// "Jan 2006" date in .TH (mandoc wants an ISO date) and literal tabs in
// filled text (from indented example lines in Long help).
func tidyMan(dir string, date time.Time) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	iso := date.Format("2006-01-02")
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".1" {
			continue
		}
		p := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		lines := strings.Split(string(b), "\n")
		for i, l := range lines {
			if strings.HasPrefix(l, ".TH ") {
				lines[i] = strings.Replace(l, date.Format("Jan 2006"), iso, 1)
				continue
			}
			lines[i] = strings.ReplaceAll(l, "\t", "    ")
		}
		if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "gen_docs:", err)
	os.Exit(1)
}
