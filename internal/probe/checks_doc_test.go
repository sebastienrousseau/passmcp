// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"errors"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// docPath is the generated inventory, relative to this package.
const docPath = "../../docs/checks.md"

// Check ids contain underscores as well as dots — protocol.malformed_json —
// so the character class has to allow them. An earlier version of this test
// did not, and quietly compared two equally-filtered halves of the
// inventory: it passed, and it was checking 22 of 76 checks.
var (
	anchorRe = regexp.MustCompile(`<span id="(check-[a-z0-9_-]+)" data-can-fail="(?:true|false)"></span>`)
	idRe     = regexp.MustCompile("<span id=\"check-[a-z0-9_-]+\" data-can-fail=\"(?:true|false)\"></span>`([^`]+)`")
)

// familySuffix marks a row whose id is built at run time.
const familySuffix = ".*"

var (
	_ = familySuffix
)

// TestDocURLMatchesInventoryAnchor is the reason doc_url can be trusted.
//
// Two programs build the same slug from the same id: scripts/checkinventory
// writes the anchor into the published page, and DocURL writes the fragment
// into every finding of every report. Nothing but this test connects them,
// and a report is read long after the run that produced it, so a fragment
// that stops resolving is a broken link in an archive nobody can regenerate.
func TestDocURLMatchesInventoryAnchor(t *testing.T) {
	b, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("reading the generated inventory: %v", err)
	}
	doc := string(b)

	ids := idRe.FindAllStringSubmatch(doc, -1)
	if len(ids) == 0 {
		t.Fatal("no check rows found; the inventory format changed and this test did not")
	}

	anchors := map[string]bool{}
	for _, m := range anchorRe.FindAllStringSubmatch(doc, -1) {
		anchors[m[1]] = true
	}

	for _, m := range ids {
		id := m[1]

		// A family row documents every id built from its prefix, so the
		// thing that has to resolve is a concrete instance, not the "*"
		// spelling that only ever appears on the page.
		if prefix, ok := strings.CutSuffix(id, familySuffix); ok {
			if !slices.Contains(DocFamilies, prefix+".") {
				t.Errorf("the inventory documents the family %q, which DocFamilies does not list: "+
					"every finding in that family would carry a dead doc_url", id)
				continue
			}
			id = prefix + ".an_observed_value"
		}

		url := DocURL(id)
		frag, ok := strings.CutPrefix(url, DocBase+"#")
		if !ok {
			t.Errorf("DocURL(%q) = %q, which is not under %q", id, url, DocBase)
			continue
		}
		if !anchors[frag] {
			t.Errorf("DocURL(%q) points at #%s, which the inventory does not define", id, frag)
		}
	}

	if got, want := len(anchors), len(ids); got != want {
		t.Errorf("%d anchors for %d check rows: an anchor without a row is a dead link too", got, want)
	}

	// The inventory's own header states the total. Reading it back is what
	// stops a narrowed regex from passing against a handful of rows, which
	// is precisely how the first version of this test went green.
	total, err := declaredCheckCount(doc)
	if err != nil {
		t.Fatalf("reading the declared check count: %v", err)
	}
	if len(ids) != total {
		t.Errorf("matched %d check rows but the inventory declares %d checks", len(ids), total)
	}
}

// TestDocURLEmptyID guards the one input that must not produce a link.
func TestDocURLEmptyID(t *testing.T) {
	if got := DocURL(""); got != "" {
		t.Errorf("DocURL(\"\") = %q, want empty: a finding with no id has nothing to point at", got)
	}
}

// declaredCheckCount reads the total the inventory states in its own prose,
// which the generator writes from the parsed call sites.
func declaredCheckCount(doc string) (int, error) {
	m := regexp.MustCompile(`passmcp runs \*\*(\d+) checks\*\*`).FindStringSubmatch(doc)
	if m == nil {
		return 0, errors.New("the inventory no longer states its own check count")
	}
	return strconv.Atoi(m[1])
}

// TestInventoryGroupsAreRealPhases keeps the published page's structure
// honest about what a phase is.
//
// The inventory groups checks by the prefix of their id, and for nine of
// them that prefix is a phase name. `stdio.*` is not: those checks run
// inside the connectivity and resilience phases and have no phase of their
// own. When they were first added the generator counted them as a tenth
// phase, so the page said "across 10 phases" while passmcp ran nine — the
// exact drift a generated page is supposed to make impossible.
//
// So: every group is either a real phase or one this test knows is not, and
// the figure the page prints counts only the former.
func TestInventoryGroupsAreRealPhases(t *testing.T) {
	b, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("reading the generated inventory: %v", err)
	}
	doc := string(b)

	// Prefixes that are deliberately not phases, with what they are. A new
	// one fails here until somebody decides which it is.
	notPhases := map[string]string{
		"stdio":  "checks that only a child-process run can make; they belong to net and resilience",
		"egress": "checks that only a watched child-process run can make; they belong to resilience, at the end of the run",
		"supply": "checks that read the target binary rather than ask the server; they belong to net",
		"fs":     "checks that only a run with planted decoys can make; they belong to resilience, after the process ends",
		"a2a":    "checks passmcp a2a check makes against an A2A agent; they are not part of an MCP run",
	}

	headings := regexp.MustCompile(`(?m)^## ([a-z0-9_-]+) — \d+ checks$`).FindAllStringSubmatch(doc, -1)
	if len(headings) == 0 {
		t.Fatal("no group headings found; the inventory format changed and this test did not")
	}

	phases := 0
	for _, m := range headings {
		name := m[1]
		if slices.Contains(PhaseNames(), name) {
			phases++
			continue
		}
		if _, known := notPhases[name]; !known {
			t.Errorf("the inventory has a %q group, which is neither a phase nor a known exception: "+
				"either add it to probe.Phases or record in this test what it is", name)
		}
	}

	m := regexp.MustCompile(`across \*\*(\d+) phases\*\*`).FindStringSubmatch(doc)
	if m == nil {
		t.Fatal("the inventory no longer states how many phases it covers")
	}
	declared, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatal(err)
	}
	if declared != phases {
		t.Errorf("the inventory says %d phases and has %d phase groups", declared, phases)
	}
	if phases > len(PhaseNames()) {
		t.Errorf("%d phase groups for %d phases", phases, len(PhaseNames()))
	}
}
