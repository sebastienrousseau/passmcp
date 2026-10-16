// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// writeFiles creates dir and the named files in it, each holding its name.
func writeFiles(t *testing.T, dir string, names ...string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("text of "+n+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLicenceFilesOnAFakeModule(t *testing.T) {
	dir := writeFiles(t, t.TempDir(), "LICENSE", "NOTICE", "COPYING.md", "license.txt", "LICENCE-MIT", "README.md", "licensing.go")
	if err := os.Mkdir(filepath.Join(dir, "LICENSES"), 0o750); err != nil {
		t.Fatal(err)
	}
	got, err := licenceFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"COPYING.md", "LICENCE-MIT", "LICENSE", "NOTICE", "license.txt"}
	if !slices.Equal(got, want) {
		t.Errorf("licenceFiles = %v, want %v", got, want)
	}
	if _, err := licenceFiles(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing module directory was read")
	}
}

// fakeGo answers the go commands notices runs from a fixed module graph.
type fakeGo struct {
	goroot string
	deps   map[string][]string // GOOS -> module paths, the main one included
	mods   []map[string]any    // go list -m -json records
	fail   string              // the first argument whose command fails
}

func (f fakeGo) run(env []string, args ...string) ([]byte, error) {
	if args[0] == f.fail || (len(args) > 1 && args[1] == f.fail) {
		return nil, errors.New("go failed")
	}
	switch {
	case args[0] == "env":
		return []byte(f.goroot + "\ngo1.99.0\n"), nil
	case slices.Equal(args, []string{"list", "-m"}):
		return []byte("example.com/self\n"), nil
	case args[1] == "-deps":
		goos := strings.TrimPrefix(env[0], "GOOS=")
		return []byte(strings.Join(f.deps[goos], "\n") + "\n"), nil
	}
	var out []byte
	for _, m := range f.mods {
		b, _ := json.Marshal(m)
		out = append(out, b...)
	}
	return out, nil
}

func useFakeGo(t *testing.T, f fakeGo) {
	t.Helper()
	prev := goCmd
	goCmd = f.run
	t.Cleanup(func() { goCmd = prev })
}

func fakeGraph(t *testing.T) fakeGo {
	root := t.TempDir()
	all := []string{"example.com/self", "example.com/apache", "example.com/apache", "github.com/mattn/go-localereader"}
	return fakeGo{
		goroot: writeFiles(t, filepath.Join(root, "goroot"), "LICENSE"),
		deps:   map[string][]string{"darwin": all[:3], "linux": all[:3], "windows": append(all, "example.com/winonly")},
		mods: []map[string]any{
			{"Path": "example.com/apache", "Version": "v1.0.0", "Dir": writeFiles(t, filepath.Join(root, "apache"), "LICENSE", "NOTICE")},
			{"Path": "example.com/winonly", "Version": "v0.1.0", "Dir": "/nonexistent",
				"Replace": map[string]any{"Version": "v0.1.1", "Dir": writeFiles(t, filepath.Join(root, "fork"), "COPYING")}},
			{"Path": "github.com/mattn/go-localereader", "Version": "v0.0.1", "Dir": writeFiles(t, filepath.Join(root, "lr"), "README.md")},
		},
	}
}

func TestRunWritesEveryLinkedModulesNotices(t *testing.T) {
	useFakeGo(t, fakeGraph(t))
	out := filepath.Join(t.TempDir(), "build", "THIRD_PARTY_NOTICES")
	if err := run(out, "./cmd/x"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	for _, want := range []string{
		"Go standard library go1.99.0\nLinked on: darwin, linux, windows",
		"example.com/apache v1.0.0\nLinked on: darwin, linux, windows",
		"--- NOTICE ---\n\ntext of NOTICE",
		"example.com/winonly v0.1.1\nLinked on: windows", // the replacement's version and files
		"--- COPYING ---",
		"github.com/mattn/go-localereader v0.0.1\nLinked on: windows",
		"Its README.md states the licence as MIT",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("notices lack %q\n%s", want, doc)
		}
	}
	if strings.Contains(doc, "example.com/self") {
		t.Error("the main module is listed as a third party")
	}
	if strings.Count(doc, "example.com/apache v1.0.0") != 1 {
		t.Error("a module linked twice is listed twice")
	}
}

func TestRunRefusesAModuleWithNoKnownLicence(t *testing.T) {
	f := fakeGraph(t)
	f.mods[0]["Dir"] = writeFiles(t, filepath.Join(t.TempDir(), "bare"), "README.md")
	useFakeGo(t, f)
	err := run(filepath.Join(t.TempDir(), "n"), "./cmd/x")
	if err == nil || !strings.Contains(err.Error(), "example.com/apache v1.0.0 ships no licence file") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunReportsEachFailure(t *testing.T) {
	cases := map[string]func(*fakeGo){
		"go env fails":             func(f *fakeGo) { f.fail = "env" },
		"go list -m fails":         func(f *fakeGo) { f.fail = "-m" },
		"go list -deps fails":      func(f *fakeGo) { f.fail = "-deps" },
		"go list -m -json fails":   func(f *fakeGo) { f.fail = "-json" },
		"module not downloaded":    func(f *fakeGo) { f.mods[0]["Dir"] = "" },
		"module directory missing": func(f *fakeGo) { f.mods[0]["Dir"] = "/nonexistent/apache" },
		"goroot has no licence":    func(f *fakeGo) { f.goroot = "/nonexistent/goroot" },
		"env prints nothing":       func(f *fakeGo) { f.goroot = "" },
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			f := fakeGraph(t)
			breakIt(&f)
			if f.fail == "-json" {
				f.fail = ""
				f.mods = append(f.mods, map[string]any{"Path": 1}) // not a module record
			}
			useFakeGo(t, f)
			if err := run(filepath.Join(t.TempDir(), "n"), "./cmd/x"); err == nil {
				t.Error("run succeeded")
			}
		})
	}
}

func TestRunCannotWriteTheOutput(t *testing.T) {
	useFakeGo(t, fakeGraph(t))
	file := writeFiles(t, t.TempDir(), "plain")
	if err := run(filepath.Join(file, "plain", "sub", "n"), "./cmd/x"); err == nil {
		t.Error("wrote under a regular file")
	}
	if err := run(t.TempDir(), "./cmd/x"); err == nil {
		t.Error("wrote over a directory")
	}
}

func TestDescribeNothing(t *testing.T) {
	if mods, err := describe(nil); mods != nil || err != nil {
		t.Errorf("describe(nil) = %v, %v", mods, err)
	}
}

// The real build graph: yaml's Apache NOTICE must reach the notices, and
// every linked module must have its terms recorded.
func TestTheShippedBinarysNotices(t *testing.T) {
	if testing.Short() {
		t.Skip("lists the real build graph for three platforms")
	}
	out := filepath.Join(t.TempDir(), "THIRD_PARTY_NOTICES")
	if err := run(out, "satellion.com/passmcp/cmd/passmcp"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"go.yaml.in/yaml/v3", "--- NOTICE ---", "Copyright 2011-2016 Canonical Ltd.", "github.com/spf13/cobra", "Go standard library"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("notices lack %q", want)
		}
	}
	if strings.Contains(string(b), "\nsatellion.com/passmcp ") {
		t.Error("passmcp lists itself")
	}
}
