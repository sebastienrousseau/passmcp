// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package supply reads what a server is made of, out of the server.
//
// passmcp scores how a server behaves on the wire and, until now, said
// nothing about the artifact behind it. For the platform-team half of the
// audience that is the first question they are asked — what is in this
// thing, and can you prove where it came from — and the one passmcp could
// not answer.
//
// For a Go server it can, with no new dependency and no network. A Go
// binary carries its own module graph: every dependency with its version
// and its h1: checksum, the toolchain that built it, the target platform,
// and — when it was built from a checkout — the commit and whether the
// tree was dirty at the time. debug/buildinfo reads all of it out of the
// file.
//
// This only applies to a stdio target, for the same reason the egress
// witness does: an endpoint is a URL, and a URL is not a file passmcp can
// open. What the operator ran is a path, and a path can be read.
//
// A dirty build is the finding worth having here. A binary whose
// vcs.modified is true cannot be traced back to any commit: the source it
// was built from does not exist in the repository, so no review of that
// repository describes what is running. It is the one provenance fact that
// is both cheap to establish and impossible to argue with.
package supply

import (
	"debug/buildinfo"
	"errors"
	"fmt"
	"os/exec"
	"runtime/debug"
	"sort"
	"strings"
)

// Build is what a binary says about itself.
type Build struct {
	// Path is the file that was read, after resolving it through PATH.
	Path string `json:"path"`
	// GoVersion is the toolchain that built it.
	GoVersion string `json:"go_version,omitempty"`
	// Main is the module the binary was built from.
	Main Module `json:"main"`
	// Deps are its dependencies, sorted by import path.
	Deps []Module `json:"dependencies,omitempty"`
	// GOOS and GOARCH are what it was built for.
	GOOS   string `json:"goos,omitempty"`
	GOARCH string `json:"goarch,omitempty"`
	// Revision is the commit it was built from, when it was built from a
	// checkout at all.
	Revision string `json:"vcs_revision,omitempty"`
	// Dirty reports that the tree had uncommitted changes when it was
	// built, so no commit describes what is running.
	Dirty bool `json:"vcs_modified"`
	// HasVCS is whether the build carried any version-control stamp. A
	// binary built from a release tarball has none, which is different
	// from one built from a dirty tree and must not be reported as it.
	HasVCS bool `json:"has_vcs_info"`
}

// Module is one entry of the graph.
type Module struct {
	Path    string `json:"path"`
	Version string `json:"version,omitempty"`
	// Sum is the h1: checksum, which is what makes this an inventory
	// somebody can verify rather than a list somebody can edit.
	Sum string `json:"sum,omitempty"`
}

// ErrNotGo means the file is not a Go binary. It is not a defect: most MCP
// servers are Python or TypeScript, and saying so is the honest answer.
var ErrNotGo = errors.New("supply: not a Go executable")

// Inspect reads the build information out of a command.
//
// The command is resolved the way a shell would resolve it, because the
// operator wrote what they would have typed: `passmcp check --stdio -- myd`
// names a program on PATH as readily as a path.
func Inspect(command string) (*Build, error) {
	if strings.TrimSpace(command) == "" {
		return nil, errors.New("supply: no command to inspect")
	}
	path, err := exec.LookPath(command)
	if err != nil {
		return nil, fmt.Errorf("supply: %w", err)
	}
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		// Distinguished so the caller can report "not a Go binary"
		// differently from "could not read the file at all".
		return nil, fmt.Errorf("%w: %s", ErrNotGo, path)
	}
	return fromBuildInfo(path, bi), nil
}

// fromBuildInfo converts what the toolchain recorded.
func fromBuildInfo(path string, bi *debug.BuildInfo) *Build {
	b := &Build{
		Path:      path,
		GoVersion: bi.GoVersion,
		Main:      Module{Path: bi.Main.Path, Version: bi.Main.Version, Sum: bi.Main.Sum},
	}
	for _, d := range bi.Deps {
		if d == nil {
			continue
		}
		// A replaced module is what actually shipped, so it is what gets
		// reported: the thing in the binary, not the thing in go.mod.
		m := d
		if d.Replace != nil {
			m = d.Replace
		}
		b.Deps = append(b.Deps, Module{Path: m.Path, Version: m.Version, Sum: m.Sum})
	}
	sort.SliceStable(b.Deps, func(i, j int) bool { return b.Deps[i].Path < b.Deps[j].Path })

	for _, s := range bi.Settings {
		switch s.Key {
		case "GOOS":
			b.GOOS = s.Value
		case "GOARCH":
			b.GOARCH = s.Value
		case "vcs.revision":
			b.Revision = s.Value
			b.HasVCS = true
		case "vcs.modified":
			b.Dirty = s.Value == "true"
			b.HasVCS = true
		}
	}
	return b
}

// Unpinned lists dependencies with no checksum.
//
// Every module the toolchain resolved normally carries one. A missing
// checksum means the module did not come from the proxy and the sum
// database never saw it — a filesystem replace, a vendored tree, or a
// local edit — so nothing about it can be verified after the fact.
func (b *Build) Unpinned() []string {
	var out []string
	for _, d := range b.Deps {
		if strings.TrimSpace(d.Sum) == "" {
			out = append(out, d.Path)
		}
	}
	sort.Strings(out)
	return out
}

// Summary is a one-line description of the artifact.
func (b *Build) Summary() string {
	var sb strings.Builder
	if b.Main.Path != "" {
		sb.WriteString(b.Main.Path)
		if b.Main.Version != "" && b.Main.Version != "(devel)" {
			sb.WriteString(" " + b.Main.Version)
		}
		sb.WriteString(", ")
	}
	fmt.Fprintf(&sb, "built with %s", b.GoVersion)
	if b.GOOS != "" && b.GOARCH != "" {
		fmt.Fprintf(&sb, " for %s/%s", b.GOOS, b.GOARCH)
	}
	fmt.Fprintf(&sb, ", %d direct and indirect dependencies", len(b.Deps))
	return sb.String()
}
