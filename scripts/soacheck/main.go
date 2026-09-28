// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Command soacheck fails when docs/compliance/iso27001-soa.md cites
// evidence that is not in the repository.
//
// The Statement of Applicability is a list of claims, each pointing at the
// file or workflow that shows it. A claim whose evidence has been renamed
// or deleted is a claim nobody can check, so the release preflight runs
// this and refuses to ship a statement that has outlived its evidence.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func main() {
	soa := flag.String("soa", "docs/compliance/iso27001-soa.md", "the Statement of Applicability")
	root := flag.String("root", ".", "the repository the evidence paths are relative to")
	flag.Parse()
	if err := run(os.Stdout, *soa, *root); err != nil {
		fmt.Fprintln(os.Stderr, "soacheck:", err)
		os.Exit(1)
	}
}

// codeSpan is one backticked path in the Evidence column.
var codeSpan = regexp.MustCompile("`([^`]+)`")

// run checks every evidence path in soa against root and reports how many
// it checked.
func run(w io.Writer, soa, root string) error {
	cited, err := evidence(soa)
	if err != nil {
		return err
	}
	if len(cited) == 0 {
		return fmt.Errorf("%s cites no evidence; the table has lost its Evidence column", soa)
	}
	var missing []string
	for _, p := range cited {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(p))); err != nil {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s cites evidence that does not exist: %s", soa, strings.Join(missing, ", "))
	}
	_, err = fmt.Fprintf(w, "soacheck: all %d cited files exist\n", len(cited))
	return err
}

// evidence returns the backticked paths in the last column of every
// table row, in order and without repeats.
func evidence(soa string) ([]string, error) {
	f, err := os.Open(soa) // #nosec G304 -- a page in the repository's own docs directory
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		for _, p := range rowEvidence(sc.Text()) {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out, sc.Err()
}

// rowEvidence returns the backticked paths in the last cell of a table
// row, or nothing for a line that is not a row.
func rowEvidence(line string) []string {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
		return nil
	}
	cells := strings.Split(strings.Trim(line, "|"), "|")
	var out []string
	for _, m := range codeSpan.FindAllStringSubmatch(cells[len(cells)-1], -1) {
		out = append(out, m[1])
	}
	return out
}
