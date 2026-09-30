// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"fmt"
	"slices"

	"satellion.com/passmcp"
)

// checkToolOrder lists the tools a second time and compares the order with
// the first listing.
//
// The specification does not require a stable order, so a reshuffle is not
// a failure. It is still a warning rather than information, because the
// cost is real and paid by every agent: a client serialises the tools into
// the model's context in the order it received them, so a server that
// answers in a different order each time changes the prompt prefix on every
// connection, and every prompt cache keyed on that prefix misses. The fix is
// one sort on the server.
func checkToolOrder(pctx func(string) context.Context, s *Session, first []passmcp.Tool) Finding {
	c := s.check("catalog.tools.order", "tools/list order is stable")
	if len(first) < 2 {
		return c.skip("fewer than two tools; there is no order to compare")
	}
	if s.toolsListRef != "" {
		c.ev(s.toolsListRef)
	}
	second, err := s.Client.ListTools(pctx("tools/list (order)"))
	if err != nil {
		return c.skip("a second tools/list failed, so there is nothing to compare: " + truncate(err.Error(), 80))
	}
	a, b := toolNames(first), toolNames(second)
	// Tool names are the server's text.
	red := s.Opts.Recorder.Redactor.String
	if !sameMembers(a, b) {
		return c.info(red(fmt.Sprintf("the catalogue changed between two consecutive listings (%d tools, then %d); order not compared", len(a), len(b))))
	}
	if i := firstDifference(a, b); i >= 0 {
		return c.warn(red(fmt.Sprintf("the same %d tools came back in a different order (first difference at position %d: %s, then %s)",
			len(a), i+1, truncate(a[i], 64), truncate(b[i], 64))),
			"return tools in a fixed order, sorted by name or by registration: a client puts them into the model's context in list order, so a reshuffle defeats prompt caching")
	}
	return c.pass(fmt.Sprintf("two listings returned the same %d tools in the same order", len(a)))
}

// toolNames lists the tools' names in order.
func toolNames(tools []passmcp.Tool) []string {
	out := make([]string, len(tools))
	for i, t := range tools {
		out[i] = t.Name
	}
	return out
}

// firstDifference is the first index where two lists differ, counting the
// end of the shorter one as a difference, or -1 when they are equal.
func firstDifference(a, b []string) int {
	for i, name := range a {
		if i >= len(b) || name != b[i] {
			return i
		}
	}
	if len(b) > len(a) {
		return len(a)
	}
	return -1
}

// sameMembers reports whether two lists hold the same names the same
// number of times, in any order.
func sameMembers(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}
