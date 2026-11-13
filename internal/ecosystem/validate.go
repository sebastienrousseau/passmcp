// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package ecosystem

import (
	"fmt"
	"sort"
	"strings"
)

// Validate reports every way the manifest contradicts itself.
//
// It returns all the problems rather than the first, because a contributor
// fixing a manifest wants the list.
func Validate() []error {
	var errs []error
	seen := map[string]bool{}
	for _, r := range Family {
		switch {
		case r.Name == "":
			errs = append(errs, fmt.Errorf("a row has no name"))
			continue
		case seen[r.Name]:
			errs = append(errs, fmt.Errorf("%s: listed twice", r.Name))
			continue
		}
		seen[r.Name] = true
		errs = append(errs, rowProblems(r)...)
	}
	if !seen["passmcp"] {
		errs = append(errs, fmt.Errorf("the manifest does not list passmcp, which is the one row that cannot be missing"))
	}
	return errs
}

// rowProblems reports what one row, already known to be named and not a
// duplicate, says that contradicts itself.
func rowProblems(r Repo) []error {
	var errs []error
	if r.Role == "" {
		errs = append(errs, fmt.Errorf("%s: no role; a row that cannot say what it is for is sprawl", r.Name))
	}
	errs = append(errs, statusProblems(r)...)
	art := map[Artefact]bool{}
	for _, a := range r.Artefacts {
		if art[a] {
			errs = append(errs, fmt.Errorf("%s: artefact %s listed twice", r.Name, a))
		}
		art[a] = true
	}
	return errs
}

// statusProblems reports what a row's status requires of it and it lacks.
func statusProblems(r Repo) []error {
	switch r.Status {
	case Released, Unreleased:
		return liveProblems(r)
	case Rejected:
		var errs []error
		if r.Reason == "" {
			errs = append(errs, fmt.Errorf("%s: rejected with no reason, so it will be re-argued in six months", r.Name))
		}
		if len(r.Artefacts) > 0 || r.Lockstep {
			errs = append(errs, fmt.Errorf("%s: rejected but carries artefacts or lockstep", r.Name))
		}
		return errs
	default:
		return []error{fmt.Errorf("%s: unknown status %q", r.Name, r.Status)}
	}
}

// liveProblems reports what a released or unreleased row lacks. Every such
// row is a real repository in the family, so it needs what the family table
// and the manual say about it, and it carries the family's version.
func liveProblems(r Repo) []error {
	var errs []error
	if r.Licence == "" {
		errs = append(errs, fmt.Errorf("%s: no licence, and the licence boundaries are the reason this family has the shape it does", r.Name))
	}
	if r.Purpose == "" || r.UseCase == "" {
		errs = append(errs, fmt.Errorf("%s: no purpose or use case, so the family table every README carries has an empty cell", r.Name))
	}
	if !r.Lockstep {
		errs = append(errs, fmt.Errorf("%s: not in lockstep; every repository in the family carries one version", r.Name))
	}
	if r.Name != "passmcp" && r.Boundary == "" {
		errs = append(errs, fmt.Errorf("%s: no boundary; every repository other than the centre must say why it is not a directory", r.Name))
	}
	if r.Name != "passmcp" && r.Kill == "" {
		errs = append(errs, fmt.Errorf("%s: no kill criterion; a satellite without one is a permanent obligation nobody agreed to", r.Name))
	}
	if r.Reason != "" {
		errs = append(errs, fmt.Errorf("%s: has a rejection reason but is not rejected", r.Name))
	}
	return errs
}

// RepoName is the GitHub repository that holds the row: Repository when it
// is set, and Name otherwise.
func (r Repo) RepoName() string {
	if r.Repository != "" {
		return r.Repository
	}
	return r.Name
}

// URL is the row's repository on GitHub.
func (r Repo) URL() string {
	return "https://github.com/sebastienrousseau/" + r.RepoName()
}

// Lookup returns the row for name.
func Lookup(name string) (Repo, bool) {
	for _, r := range Family {
		if r.Name == name {
			return r, true
		}
	}
	return Repo{}, false
}

// ByStatus returns the rows with the given status, in manifest order.
func ByStatus(s Status) []Repo {
	var out []Repo
	for _, r := range Family {
		if r.Status == s {
			out = append(out, r)
		}
	}
	return out
}

// ArtefactList renders a row's artefacts as a sorted, comma-separated string,
// for a generated table.
func (r Repo) ArtefactList() string {
	out := make([]string, len(r.Artefacts))
	for i, a := range r.Artefacts {
		out[i] = string(a)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}
