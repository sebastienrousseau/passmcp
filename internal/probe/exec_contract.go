// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"fmt"

	"satellion.com/passmcp"
)

// uriRead is one resources/read that returned contents: the URI asked
// for, the URIs the contents came back under, and the requests it took.
type uriRead struct {
	requested string
	got       []string
	from, to  int
}

// noteURIs records the URIs a read's contents were filed under. A read
// with no contents is not recorded: there is nothing to compare, and
// execution.resources already reports it.
func (e *execRun) noteURIs(requested string, contents []passmcp.ResourceContents, from, to int) {
	if len(contents) == 0 {
		return
	}
	r := uriRead{requested: requested, from: from, to: to}
	for _, c := range contents {
		r.got = append(r.got, c.URI)
	}
	e.uriReads = append(e.uriReads, r)
}

// mismatch describes how a read's contents disagree with the URI asked
// for, or returns "" when one of them is filed under it.
//
// A read may return more than one item — a directory-like resource
// answers with its children — so the rule is that the resource asked for
// is among them, not that every item repeats its URI. An item with no uri
// at all is wrong either way: the field is required.
func (r uriRead) mismatch() string {
	found := false
	for i, u := range r.got {
		if u == "" {
			return fmt.Sprintf("%s returned contents[%d] with no uri", truncate(r.requested, 80), i)
		}
		found = found || u == r.requested
	}
	if found {
		return ""
	}
	return fmt.Sprintf("%s returned %s", truncate(r.requested, 80), truncate(r.got[0], 80))
}

// resourceURIFinding judges whether each read's contents came back under
// the URI requested, citing the reads that showed it.
func (e *execRun) resourceURIFinding() Finding {
	s := e.s
	c := s.check("execution.resources.uri", "Resource reads return the URI requested")
	if len(e.uriReads) == 0 {
		return c.skip("no resource read returned contents to compare")
	}
	var bad []string
	for _, r := range e.uriReads {
		if m := r.mismatch(); m != "" {
			bad = append(bad, m)
			c.ev(reqRef(r.from, r.to))
		}
	}
	if len(bad) > 0 {
		// The URIs are the server's text.
		return c.warn(s.Opts.Recorder.Redactor.String(summariseIssues(bad)),
			"file each read's contents under the uri the client asked for: a client holding several resources matches contents to requests by that field")
	}
	last := e.uriReads[len(e.uriReads)-1]
	c.ev(reqRef(e.uriReads[0].from, last.to))
	return c.pass(fmt.Sprintf("%s returned contents under the URI requested", plural(len(e.uriReads), "read")))
}
