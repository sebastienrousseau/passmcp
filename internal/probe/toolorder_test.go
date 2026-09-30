// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"strings"
	"testing"
)

func TestToolListOrder(t *testing.T) {
	// The same order twice passes, citing both listings.
	fs := catalogOnly(t, newFakeServer(t))
	expect(t, fs, "catalog.tools.order", Pass, "same order")
	ev := fs["catalog.tools.order"].Evidence
	if len(ev) != 2 || ev[0] != fs["catalog.tools.list"].Evidence[0] || ev[0] == ev[1] {
		t.Errorf("want both listings cited, the first being catalog.tools.list's: %v vs %v", ev, fs["catalog.tools.list"].Evidence)
	}

	// The same tools reordered warn, naming where they first differ.
	f := newFakeServer(t)
	f.q.toolOrder = "shuffle"
	fs = catalogOnly(t, f)
	expect(t, fs, "catalog.tools.order", Warn, "different order")
	if got := fs["catalog.tools.order"]; got.Severity != Minor || len(got.Evidence) != 2 || !strings.Contains(got.Detail, "position 1") {
		t.Errorf("want a minor warning citing both listings: %+v", got)
	}

	// A catalogue that changed in between is noted, not judged on order.
	f = newFakeServer(t)
	f.q.toolOrder = "grow"
	expect(t, catalogOnly(t, f), "catalog.tools.order", Info, "changed between")

	// A second listing that fails leaves nothing to compare.
	f = newFakeServer(t)
	f.q.toolOrder = "failsecond"
	fs = catalogOnly(t, f)
	expect(t, fs, "catalog.tools.list", Pass, "")
	expect(t, fs, "catalog.tools.order", Skip, "second tools/list failed")

	// One tool has no order, and no request is spent finding that out.
	f = newFakeServer(t)
	f.q.catalog = "noschema"
	fs = catalogOnly(t, f)
	expect(t, fs, "catalog.tools.order", Skip, "fewer than two")
	if len(fs["catalog.tools.order"].Evidence) != 0 {
		t.Errorf("no request should be made: %v", fs["catalog.tools.order"].Evidence)
	}
}

func TestFirstDifference(t *testing.T) {
	if i := firstDifference([]string{"a", "b"}, []string{"a", "b"}); i != -1 {
		t.Errorf("equal lists: %d", i)
	}
	if i := firstDifference([]string{"a", "b", "c"}, []string{"a", "c", "b"}); i != 1 {
		t.Errorf("differ at 1: %d", i)
	}
	if firstDifference([]string{"a"}, []string{"a", "b"}) != 1 || firstDifference([]string{"a", "b"}, []string{"a"}) != 1 {
		t.Error("a longer list differs where the shorter one ends")
	}
	if sameMembers([]string{"a", "b"}, []string{"b", "c"}) || !sameMembers([]string{"a", "b", "a"}, []string{"a", "a", "b"}) || sameMembers([]string{"a"}, []string{"a", "a"}) {
		t.Error("sameMembers")
	}
}
