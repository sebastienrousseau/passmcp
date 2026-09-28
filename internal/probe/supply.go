// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"errors"
	"fmt"
	"strings"

	"satellion.com/passmcp/internal/supply"
)

// What the server is, as opposed to how it behaves.
//
// Every other phase asks the server questions and reads the answers. This
// one reads the file, which is the only part of a diagnostic that cannot
// be influenced by the thing being diagnosed: a server can answer however
// it likes, and its own binary still says which modules went into it and
// whether the tree it was built from was clean.
//
// Only for a stdio target. An endpoint is a URL and a URL is not a file.

// checkSupplyChain reports what the server is made of.
func checkSupplyChain(s *Session) []Finding {
	if !s.overStdio() || s.Opts.Stdio == nil {
		return nil
	}
	return inspectTarget(s)
}

// inspectTarget is the body, without the guard, so a test can reach the
// branches that do not need a running process.
func inspectTarget(s *Session) []Finding {
	c := s.check("supply.buildinfo", "What the server binary is made of")

	build, err := supply.Inspect(s.Opts.Stdio.Command)
	switch {
	case errors.Is(err, supply.ErrNotGo):
		// Most MCP servers are Python or TypeScript. Saying so is the
		// answer, not a failure: the manifest formats those use are a
		// separate piece of work and their absence here is not a defect
		// in the server.
		return []Finding{c.info("not a Go binary, so it carries no embedded module graph; " +
			"a manifest-based inventory for other ecosystems is not implemented yet")}
	case err != nil:
		return []Finding{c.info("could not read the program: " + err.Error())}
	}
	s.Build = build

	out := []Finding{c.ev(buildEvidence(build)).info(build.Summary())}
	return append(out, provenanceFinding(s, build))
}

// provenanceFinding answers whether the binary can be traced to a commit.
func provenanceFinding(s *Session, b *supply.Build) Finding {
	c := s.check("supply.provenance", "The binary can be traced to a commit")

	if !b.HasVCS {
		// A release tarball has no VCS stamp, and that is ordinary rather
		// than suspicious. Reported so a reader knows the question was
		// asked and could not be answered, which is different from it
		// having been answered well.
		return c.info("no version-control stamp, which is what a build from a source archive " +
			"looks like; there is nothing here to trace back to a commit either way")
	}

	if b.Dirty {
		return c.ev(b.Revision).fail(Major,
			"built from a tree with uncommitted changes (vcs.modified=true), at "+shortRev(b.Revision),
			"build from a clean checkout. A dirty build cannot be traced to any commit: the source "+
				"it was made from does not exist in the repository, so no review of that repository "+
				"describes what is actually running")
	}

	detail := "built from " + shortRev(b.Revision) + " with a clean tree"
	if unpinned := b.Unpinned(); len(unpinned) > 0 {
		// Clean tree, unverifiable contents. Worth separating: the commit
		// is knowable and some of what went in is not.
		return c.ev(b.Revision).warn(
			detail+", but "+plural(len(unpinned), "dependency")+" carry no checksum: "+list(unpinned),
			"a module with no h1: sum did not come through the module proxy and the checksum "+
				"database never saw it, so nothing about it can be verified after the fact. A local "+
				"replace or a vendored tree is the usual cause")
	}
	return c.ev(b.Revision).pass(detail)
}

// buildEvidence renders the graph for a finding's evidence, bounded.
func buildEvidence(b *supply.Build) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s; go %s", b.Path, b.GoVersion)
	if b.Revision != "" {
		fmt.Fprintf(&sb, "; %s", shortRev(b.Revision))
	}
	shown := min(len(b.Deps), 10)
	for i := range shown {
		fmt.Fprintf(&sb, "; %s %s", b.Deps[i].Path, b.Deps[i].Version)
	}
	if len(b.Deps) > shown {
		fmt.Fprintf(&sb, "; and %d more", len(b.Deps)-shown)
	}
	return sb.String()
}

// shortRev abbreviates a commit the way a person writes one.
func shortRev(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	if rev == "" {
		return "an unrecorded revision"
	}
	return rev
}
