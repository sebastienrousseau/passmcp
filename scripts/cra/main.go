// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build ignore

// cra runs the EU Cyber Resilience Act evidence checks in internal/cra from
// the command line, for the release preflight, the release workflow and
// the published-release audit.
//
//	go run ./scripts/cra/main.go preflight
//	go run ./scripts/cra/main.go release-assets --tag v0.0.1
//	go run ./scripts/cra/main.go release-assets --assets-file names.txt
//	govulncheck -format json ./... | go run ./scripts/cra/main.go vex --product pkg:golang/satellion.com/passmcp@v0.0.1 --out passmcp.openvex.json
//
// Every subcommand prints what it checked and exits 1 on any problem.
// Diagnostics go to stderr; `vex` writes its document to --out.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"satellion.com/passmcp/internal/cra"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: cra preflight | release-assets | vex | validate-vex | security-txt")
	}
	var err error
	switch os.Args[1] {
	case "preflight":
		err = preflight()
	case "release-assets":
		err = releaseAssets(os.Args[2:])
	case "vex":
		err = vex(os.Args[2:])
	case "validate-vex":
		err = validateVEX(os.Args[2:])
	case "security-txt":
		err = securityTxt(os.Args[2:])
	default:
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "cra:", msg)
	os.Exit(1)
}

// report prints problems and turns them into an error.
func report(what string, problems []string) error {
	if len(problems) == 0 {
		fmt.Fprintln(os.Stderr, "cra: "+what+": ok")
		return nil
	}
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, "cra: "+p)
	}
	return fmt.Errorf("%s: %d problem(s)", what, len(problems))
}

// preflight checks the security policy (CRA-01), the compliance page's
// claims (CRA-03) and every release highlights file's advisories (CRA-04).
func preflight() error {
	policy, err := os.ReadFile("SECURITY.md")
	if err != nil {
		return err
	}
	var problems []string
	problems = append(problems, cra.CheckSecurityPolicy(string(policy))...)
	page := "docs/compliance/cra.md"
	md, err := os.ReadFile(page)
	if err != nil {
		return err
	}
	problems = append(problems, cra.CheckClaims(string(md), page, exists)...)
	notes, _ := filepath.Glob("docs/releases/v*.md")
	sort.Strings(notes)
	for _, n := range notes {
		b, err := os.ReadFile(n)
		if err != nil {
			return err
		}
		for _, p := range cra.CheckAdvisoryNotes(string(b)) {
			problems = append(problems, n+": "+p)
		}
	}
	return report("security policy, CRA claims and release advisories", problems)
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// releaseAssets audits a published release's asset list (CRA-02).
func releaseAssets(args []string) error {
	fs := flag.NewFlagSet("release-assets", flag.ExitOnError)
	tag := fs.String("tag", "", "release tag to read the asset list of, with gh")
	repo := fs.String("repo", "sebastienrousseau/passmcp", "repository")
	file := fs.String("assets-file", "", "read asset names, one per line, from this file instead")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var names []string
	var err error
	switch {
	case *file != "":
		names, err = readLines(*file)
	case *tag != "":
		names, err = ghAssets(*repo, *tag)
	default:
		return fmt.Errorf("release-assets needs --tag or --assets-file")
	}
	if err != nil {
		return err
	}
	return report(fmt.Sprintf("release assets (%d)", len(names)), cra.CheckReleaseAssets(names))
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path) // #nosec G304 -- a path the operator passed on the command line
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}

func ghAssets(repo, tag string) ([]string, error) {
	out, err := exec.Command("gh", "release", "view", tag, "-R", repo, "--json", "assets", "--jq", ".assets[].name").Output() // #nosec G204 -- fixed program, operator-supplied tag
	if err != nil {
		return nil, fmt.Errorf("reading the assets of %s: %w", tag, err)
	}
	return strings.Fields(string(out)), nil
}

// vex turns govulncheck's JSON on stdin (or --in) into an OpenVEX document
// (CRA-04), validates it, and writes it to --out.
func vex(args []string) error {
	fs := flag.NewFlagSet("vex", flag.ExitOnError)
	product := fs.String("product", "", "package URL of the release, e.g. pkg:golang/satellion.com/passmcp@v0.0.1")
	author := fs.String("author", "Sebastien Rousseau <sebastian.rousseau@gmail.com>", "document author")
	in := fs.String("in", "", "govulncheck -format json output (default stdin)")
	out := fs.String("out", "", "where to write the OpenVEX document")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *product == "" || *out == "" {
		return fmt.Errorf("vex needs --product and --out")
	}
	var r io.Reader = os.Stdin
	if *in != "" {
		f, err := os.Open(*in) // #nosec G304 -- a path the operator passed on the command line
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}
	doc, err := cra.BuildVEX(r, *product, *author, time.Now())
	if err != nil {
		return err
	}
	if err := report("OpenVEX document", cra.ValidateVEX(doc)); err != nil {
		return err
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, append(b, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "cra: %d statement(s), %d not affected, written to %s\n", len(doc.Statements), doc.NotAffected(), *out)
	return nil
}

// securityTxt checks a security.txt (CRA-05), from a file or, for the
// published-release audit, from a URL.
func securityTxt(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("security-txt needs a file or an https URL")
	}
	var body []byte
	var err error
	if strings.HasPrefix(args[0], "https://") {
		body, err = exec.Command("curl", "-fsSL", "--max-time", "20", args[0]).Output() // #nosec G204 -- fixed program, operator-supplied URL
	} else {
		body, err = os.ReadFile(args[0])
	}
	if err != nil {
		return fmt.Errorf("reading %s: %w", args[0], err)
	}
	return report("security.txt "+args[0], cra.CheckSecurityTxt(string(body), time.Now()))
}

// validateVEX checks an existing OpenVEX document.
func validateVEX(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("validate-vex needs one file")
	}
	b, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	var doc cra.VEX
	if err := json.Unmarshal(b, &doc); err != nil {
		return err
	}
	return report("OpenVEX document "+args[0], cra.ValidateVEX(doc))
}
