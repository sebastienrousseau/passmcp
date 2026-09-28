// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"fmt"
	"sort"
	"strings"

	"satellion.com/passmcp/internal/egress"
)

// Every other check in this report asks what the server said. This one
// asks where it went.
//
// A server that posts your tool arguments to a third host passes all of
// them: the catalogue is clean, the schemas validate, the annotations are
// honest, and the destination appears in no document anywhere, because not
// appearing is the point. The only way to find it is to be the thing it
// dials through — which passmcp can be, over stdio, because it set the
// child's environment.
//
// What this reports and what it judges are deliberately different. Almost
// every server that dials out is doing its job: a GitHub server talks to
// GitHub. passmcp cannot know which host is legitimate for a server it was
// handed five seconds ago, so by default it inventories rather than
// accuses. The operator supplies the expectation, and then the same
// evidence becomes a gate.

// checkEgress reports where the server went.
func checkEgress(s *Session) []Finding {
	if s.Proxy == nil {
		if s.egressErr != "" {
			// Asked for and unavailable. "No connections" would be a
			// false reassurance, which is the one answer this must never
			// give.
			c := s.check("egress.hosts", "Where the server connected")
			return []Finding{c.info("the egress witness could not start, so nothing was watched: " + s.egressErr)}
		}
		return nil
	}
	dials := s.Proxy.Dials()

	c := s.check("egress.hosts", "Where the server connected")
	if len(dials) == 0 {
		// Worth stating rather than omitting. A server that reached for
		// nothing is a smaller thing to trust than one that did, and a
		// report that says nothing here reads as a check that did not run.
		return append([]Finding{c.pass("the server made no outbound connection during the run")},
			checkExpectedEgress(s, dials)...)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%d destination(s): ", len(dials))
	for i, d := range dials {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s ×%d", d.Target(), d.Count)
		if !d.Allowed {
			b.WriteString(" (refused)")
		}
	}
	// An observation, not a verdict: passmcp has no way to know which of
	// these a server is supposed to reach.
	return append([]Finding{c.ev(egressEvidence(dials)).info(b.String())},
		checkExpectedEgress(s, dials)...)
}

// checkExpectedEgress turns the same evidence into a gate, once the
// operator has said what they expect.
func checkExpectedEgress(s *Session, dials []egress.Dial) []Finding {
	expected := s.Opts.ExpectEgress
	c := s.check("egress.undeclared_host", "The server went only where it was expected to")
	if len(expected) == 0 {
		return []Finding{c.skip("no --expect-egress was given, so there is nothing to measure " +
			"the destinations against; egress.hosts lists them")}
	}

	var undeclared []string
	for _, d := range dials {
		if !hostExpected(d.Host, expected) {
			undeclared = append(undeclared, d.Target())
		}
	}
	sort.Strings(undeclared)

	if len(undeclared) == 0 {
		return []Finding{c.pass(fmt.Sprintf(
			"every destination was one of the %d expected", len(expected)))}
	}
	return []Finding{c.ev(egressEvidence(dials)).fail(Critical,
		"connected to "+strings.Join(undeclared, ", ")+", which --expect-egress does not name",
		"confirm what the server is reaching for. A destination nobody declared is either a "+
			"dependency the operator did not know about or a place the server is sending what "+
			"it was given, and the two look identical from here")}
}

// hostExpected matches a host against the operator's list, allowing a
// leading dot to mean "and anything under it".
func hostExpected(host string, expected []string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	for _, e := range expected {
		e = strings.ToLower(strings.TrimSpace(e))
		switch {
		case e == "":
			continue
		case strings.HasPrefix(e, "."):
			if h == strings.TrimPrefix(e, ".") || strings.HasSuffix(h, e) {
				return true
			}
		case h == e:
			return true
		}
	}
	return false
}

// egressEvidence renders the dials for a finding's evidence.
func egressEvidence(dials []egress.Dial) string {
	if len(dials) == 0 {
		return "no outbound connection"
	}
	parts := make([]string, 0, len(dials))
	for _, d := range dials {
		how := "plain"
		if d.Tunnelled {
			how = "CONNECT"
		}
		parts = append(parts, fmt.Sprintf("%s %s ×%d at +%s", how, d.Target(), d.Count, d.First))
	}
	return strings.Join(parts, "; ")
}
