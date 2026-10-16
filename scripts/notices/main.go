// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Command notices writes THIRD_PARTY_NOTICES: the licence and notice files
// of every module the released passmcp binary links, reproduced in full.
//
// The release binaries are static, so the MIT, BSD and Apache-2.0 code in
// them ships with them, and those licences ask for their text (and, for
// Apache-2.0, the NOTICE file) to go wherever the binary goes. The list is
// derived from the build graph rather than kept by hand: for each target
// operating system it asks `go list -deps` which modules ./cmd/passmcp
// links, then copies every LICENSE*, LICENCE*, COPYING* and NOTICE* file
// from each module's directory, as `go list -m -json` reports it. The Go
// standard library's licence comes first, since it is linked too.
//
//	go run ./scripts/notices            # writes build/THIRD_PARTY_NOTICES
//	go run ./scripts/notices -o FILE
//
// The output is generated, never committed. A linked module that ships no
// licence file fails the run unless knownUnlicensed says what is known
// about it, so a new dependency without one is a decision somebody makes
// rather than a gap nobody sees.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// targets are the operating systems goreleaser builds for. The operating
// system changes which modules are linked (golang.org/x/text and
// go-localereader are linked on Windows only); the architecture does not.
var targets = []string{"darwin", "linux", "windows"}

// knownUnlicensed records linked modules that ship no licence file, with
// what their own documentation says. It states what the module says and
// nothing more: where the module names no copyright holder, none is given.
var knownUnlicensed = map[string]string{
	"github.com/mattn/go-localereader": "This module ships no LICENSE, COPYING or NOTICE file. " +
		"Its README.md states the licence as MIT. No copyright notice is " +
		"published with it, so none is reproduced here.",
}

// module is one linked module and the licence files found for it.
type module struct {
	Path    string
	Version string
	Dir     string
	OSes    []string
	Files   []string // licence and notice file names, relative to Dir
}

// goCmd runs the go command with extra environment and returns its
// stdout. A variable so tests can run without a module cache.
var goCmd = func(env []string, args ...string) ([]byte, error) {
	cmd := exec.Command("go", args...) //nolint:gosec // the go command, with arguments this program builds
	cmd.Env = append(os.Environ(), env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func main() {
	out := flag.String("o", "build/THIRD_PARTY_NOTICES", "file to write")
	pkg := flag.String("pkg", "./cmd/passmcp", "the package whose dependencies are listed")
	flag.Parse()
	if err := run(*out, *pkg); err != nil {
		fmt.Fprintln(os.Stderr, "notices:", err)
		os.Exit(1)
	}
}

func run(out, pkg string) error {
	std, err := stdlib()
	if err != nil {
		return err
	}
	mods, err := linked(pkg)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := render(&buf, append([]module{std}, mods...)); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
		return err
	}
	// A licence notice is public text, meant to be read by anyone.
	if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil { //nolint:gosec // world-readable on purpose
		return err
	}
	fmt.Fprintf(os.Stderr, "notices: the standard library and %d modules written to %s\n", len(mods), out)
	return nil
}

// stdlib describes the Go standard library of the toolchain in use.
func stdlib() (module, error) {
	b, err := goCmd(nil, "env", "GOROOT", "GOVERSION")
	if err != nil {
		return module{}, err
	}
	v := lines(b)
	if len(v) != 2 {
		return module{}, fmt.Errorf("go env GOROOT GOVERSION printed %q", b)
	}
	return module{Path: "Go standard library", Version: v[1], Dir: v[0], OSes: targets, Files: []string{"LICENSE"}}, nil
}

// linked returns every module other than the main one that pkg links on
// any target, sorted by path, with the licence files in its directory.
func linked(pkg string) ([]module, error) {
	oses, err := linkedPaths(pkg)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(oses))
	for p := range oses {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	mods, err := describe(paths)
	if err != nil {
		return nil, err
	}
	for i := range mods {
		m := &mods[i]
		m.OSes = oses[m.Path]
		if m.Files, err = licenceFiles(m.Dir); err != nil {
			return nil, err
		}
		if len(m.Files) == 0 && knownUnlicensed[m.Path] == "" {
			return nil, fmt.Errorf("%s %s ships no licence file; establish its terms and record them in knownUnlicensed", m.Path, m.Version)
		}
	}
	return mods, nil
}

// linkedPaths maps each module pkg links to the targets that link it.
func linkedPaths(pkg string) (map[string][]string, error) {
	b, err := goCmd(nil, "list", "-m")
	if err != nil {
		return nil, err
	}
	self := strings.TrimSpace(string(b))
	oses := map[string][]string{}
	for _, goos := range targets {
		b, err := goCmd([]string{"GOOS=" + goos}, "list", "-deps", "-f", "{{with .Module}}{{.Path}}{{end}}", pkg)
		if err != nil {
			return nil, err
		}
		for _, p := range lines(b) {
			if p != self && !slices.Contains(oses[p], goos) {
				oses[p] = append(oses[p], goos)
			}
		}
	}
	return oses, nil
}

// describe asks the go command for each module's version and directory.
func describe(paths []string) ([]module, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	b, err := goCmd(nil, append([]string{"list", "-m", "-json"}, paths...)...)
	if err != nil {
		return nil, err
	}
	var mods []module
	dec := json.NewDecoder(bytes.NewReader(b))
	for {
		var m struct {
			Path, Version, Dir string
			Replace            *struct{ Version, Dir string }
		}
		if err := dec.Decode(&m); errors.Is(err, io.EOF) {
			return mods, nil
		} else if err != nil {
			return nil, err
		}
		if m.Replace != nil {
			m.Version, m.Dir = m.Replace.Version, m.Replace.Dir
		}
		if m.Dir == "" {
			return nil, fmt.Errorf("%s %s is not in the module cache; run go mod download", m.Path, m.Version)
		}
		mods = append(mods, module{Path: m.Path, Version: m.Version, Dir: m.Dir})
	}
}

// licenceFiles names the licence and notice files at the top of dir.
func licenceFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.Type().IsRegular() && isLicenceFile(e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

func isLicenceFile(name string) bool {
	up := strings.ToUpper(name)
	for _, prefix := range []string{"LICENSE", "LICENCE", "COPYING", "NOTICE"} {
		if strings.HasPrefix(up, prefix) {
			return true
		}
	}
	return false
}

var rule = strings.Repeat("=", 78)

// render writes the notices document.
func render(w io.Writer, mods []module) error {
	bw := bufio.NewWriter(w)
	_, _ = fmt.Fprintf(bw, "Third-party notices for passmcp\n\n"+
		"passmcp is licensed under GPL-3.0-only (see LICENSE). Its binaries are\n"+
		"statically linked and include the software listed below, whose licence\n"+
		"and notice files are reproduced in full. Generated by scripts/notices\n"+
		"from the build graph for %s.\n", strings.Join(targets, ", "))
	for _, m := range mods {
		_, _ = fmt.Fprintf(bw, "\n%s\n%s %s\nLinked on: %s\n%s\n", rule, m.Path, m.Version, strings.Join(m.OSes, ", "), rule)
		if len(m.Files) == 0 {
			_, _ = fmt.Fprintf(bw, "\n%s\n", knownUnlicensed[m.Path])
			continue
		}
		for _, f := range m.Files {
			b, err := os.ReadFile(filepath.Join(m.Dir, f)) //nolint:gosec // a file in a module directory the go command named
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(bw, "\n--- %s ---\n\n%s\n", f, strings.TrimRight(string(b), "\n"))
		}
	}
	return bw.Flush()
}

// lines splits go command output into its non-empty lines.
func lines(b []byte) []string {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}
