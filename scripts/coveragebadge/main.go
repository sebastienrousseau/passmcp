// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Command coveragebadge reads a Go cover profile and writes the shields.io
// endpoint document behind the README's coverage badge, so the number on the
// badge is the number CI measured and never one typed by hand.
//
//	go test -coverprofile=coverage.out ./...
//	go run ./scripts/coveragebadge -profile coverage.out > coverage.json
//
// The document goes to stdout and diagnostics to stderr. A statement counts
// as covered when any test executed it; a block the profile lists more than
// once (one entry per test binary that compiled it) is counted once.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// badge is a shields.io endpoint document
// (https://shields.io/badges/endpoint-badge).
type badge struct {
	SchemaVersion int    `json:"schemaVersion"`
	Label         string `json:"label"`
	Message       string `json:"message"`
	Color         string `json:"color"`
}

// block is one entry of a cover profile.
type block struct {
	stmts   int64
	covered bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the command without the process around it: it returns the exit
// status, writes the document to stdout and every diagnostic to stderr.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("coveragebadge", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profile := fs.String("profile", "", "Go cover profile to read (required)")
	exclude := fs.String("exclude", "", "comma-separated substrings; blocks in files containing one are not counted")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *profile == "" {
		_, _ = fmt.Fprintln(stderr, "coveragebadge: -profile is required")
		return 2
	}
	pct, err := measure(*profile, splitList(*exclude))
	if err == nil {
		err = json.NewEncoder(stdout).Encode(badgeFor(pct))
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "coveragebadge:", err)
		return 1
	}
	return 0
}

// measure opens a profile and returns its statement coverage in percent.
func measure(path string, exclude []string) (float64, error) {
	f, err := os.Open(path) // #nosec G304 -- the path is the operator's own flag
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	blocks, err := parseProfile(f, exclude)
	if err != nil {
		return 0, err
	}
	return percent(blocks)
}

// parseProfile reads the blocks of a cover profile, keyed by file and range,
// skipping files that contain any of the exclude substrings.
func parseProfile(r io.Reader, exclude []string) (map[string]block, error) {
	blocks := map[string]block{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "mode:") {
			continue
		}
		key, b, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		if excluded(key, exclude) {
			continue
		}
		prev := blocks[key]
		blocks[key] = block{stmts: b.stmts, covered: prev.covered || b.covered}
	}
	return blocks, sc.Err()
}

// parseLine splits "file.go:1.2,3.4 stmts count" into its key and block.
func parseLine(line string) (string, block, error) {
	fields := strings.Fields(line)
	if len(fields) != 3 || !strings.Contains(fields[0], ":") {
		return "", block{}, fmt.Errorf("not a cover profile block: %q", line)
	}
	stmts, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || stmts < 0 {
		return "", block{}, fmt.Errorf("bad statement count %q", fields[1])
	}
	count, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || count < 0 {
		return "", block{}, fmt.Errorf("bad execution count %q", fields[2])
	}
	return fields[0], block{stmts: stmts, covered: count > 0}, nil
}

// excluded reports whether the block's file matches any exclude substring.
func excluded(key string, exclude []string) bool {
	file := key[:strings.LastIndex(key, ":")]
	for _, e := range exclude {
		if strings.Contains(file, e) {
			return true
		}
	}
	return false
}

// percent is covered statements over all statements.
func percent(blocks map[string]block) (float64, error) {
	var total, covered int64
	for _, b := range blocks {
		total += b.stmts
		if b.covered {
			covered += b.stmts
		}
	}
	if total == 0 {
		return 0, errors.New("the profile has no statements to measure")
	}
	return 100 * float64(covered) / float64(total), nil
}

// badgeFor renders a percentage with the family's colour bands: brightgreen
// from 90, green from 85 (the gate), yellow from 70, red below.
func badgeFor(pct float64) badge {
	// Truncate rather than round, so the badge never shows the gate as met
	// when it is not: 84.96% reads 84.9%, not 85.0%.
	shown := float64(int64(pct*10)) / 10
	color := "red"
	switch {
	case shown >= 90:
		color = "brightgreen"
	case shown >= 85:
		color = "green"
	case shown >= 70:
		color = "yellow"
	}
	return badge{
		SchemaVersion: 1,
		Label:         "coverage",
		Message:       strconv.FormatFloat(shown, 'f', 1, 64) + "%",
		Color:         color,
	}
}

// splitList turns "a,b" into its non-empty, trimmed parts.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
