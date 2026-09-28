// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package controls

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// inventoryPath is the generated check inventory, which is itself held to
// the source by `make checks-verify`. Reading it here makes the mapping
// gate transitive: a check added to the code is in the inventory, and a
// check in the inventory must be in every mapping.
const inventoryPath = "../../docs/checks.md"

var inventoryIDRe = regexp.MustCompile("<span id=\"check-[a-z0-9_-]+\" data-can-fail=\"(?:true|false)\"></span>`([^`]+)`")

func inventory(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(inventoryPath)
	if err != nil {
		t.Fatalf("reading the inventory: %v", err)
	}
	var ids []string
	for _, m := range inventoryIDRe.FindAllStringSubmatch(string(b), -1) {
		ids = append(ids, m[1])
	}
	if len(ids) < 100 {
		t.Fatalf("found %d checks in the inventory; its format changed and this test did not", len(ids))
	}
	return ids
}

func mustLoad(t *testing.T, f Framework) *Mapping {
	t.Helper()
	m, err := Load(f)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// AC: SOC2-02
func TestSOC2MappingCoversEveryCheck(t *testing.T) {
	for _, p := range mustLoad(t, SOC2).Problems(inventory(t)) {
		t.Error(p)
	}
}

// AC: ISO-02
func TestISOMappingCoversEveryCheckWith2022Controls(t *testing.T) {
	m := mustLoad(t, ISO27001)
	for _, p := range m.Problems(inventory(t)) {
		t.Error(p)
	}
	annex, err := AnnexA()
	if err != nil {
		t.Fatal(err)
	}
	if len(annex) != 93 {
		t.Fatalf("Annex A (2022) has 93 controls; the list has %d", len(annex))
	}
	valid := map[string]bool{}
	for _, c := range annex {
		valid[c.ID] = true
	}
	// Every criterion and every mapped control is a 2022 identifier. The
	// 2013 edition's A.9–A.18 cannot survive: 2022 has only A.5–A.8.
	for _, c := range m.Criteria {
		if !valid[c.ID] {
			t.Errorf("criterion %s is not an ISO/IEC 27001:2022 Annex A control", c.ID)
		}
	}
	for id, e := range m.Checks {
		for _, c := range e.Controls {
			if !valid[c] {
				t.Errorf("%s maps to %s, which is not a 2022 Annex A control", id, c)
			}
		}
	}
	if len(m.Criteria) != 93 {
		t.Errorf("the ISO mapping lists %d controls, not all 93", len(m.Criteria))
	}
}

// AC: GDPR-06
func TestGDPRMappingCoversEveryCheck(t *testing.T) {
	for _, p := range mustLoad(t, GDPR).Problems(inventory(t)) {
		t.Error(p)
	}
}

// The gate must actually fail: a check the mapping lacks, a control the
// framework does not define and an unexplained gap are each reported.
func TestProblemsReportsEachDefect(t *testing.T) {
	m := &Mapping{
		Framework: SOC2,
		Criteria:  []Criterion{{ID: "CC6.1"}, {ID: "CC1.1"}, {ID: "CC7.1", Reason: "stale"}},
		Checks: map[string]Entry{
			"a.mapped":   {Controls: []string{"CC6.1", "CC9.9", "CC7.1"}},
			"b.empty":    {},
			"c.both":     {Controls: []string{"CC6.1"}, None: "x"},
			"z.orphaned": {None: "no longer a check"},
		},
	}
	got := strings.Join(m.Problems([]string{"a.mapped", "b.empty", "c.both", "d.new"}), "\n")
	for _, want := range []string{
		"check d.new has no entry",
		"entry z.orphaned names no check",
		"b.empty maps to nothing and gives no reason",
		"c.both maps to controls and also says none",
		"CC9.9, which the framework does not define",
		"CC1.1 is evidenced by no check and gives no reason",
		"CC7.1 is evidenced by a check but still says why it is not",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Problems did not report %q; got:\n%s", want, got)
		}
	}
}

// AC: SOC2-01, ISO-01
func TestForMarshalsEveryFrameworkAsAList(t *testing.T) {
	b, err := json.Marshal(For("net.tls.cert"))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string][]string
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !contains(got["soc2"], "CC6.7") || !contains(got["iso27001"], "A.8.24") || !contains(got["gdpr"], "Art. 32") {
		t.Errorf("net.tls.cert controls = %s", b)
	}
	// A check that evidences nothing, and one no mapping knows, still
	// carry three lists: never null, never missing.
	for _, id := range []string{"net.dns", "not.a.check"} {
		b, _ := json.Marshal(For(id))
		if string(b) != `{"soc2":[],"iso27001":[],"gdpr":[]}` {
			t.Errorf("For(%q) = %s, want three empty lists", id, b)
		}
	}
}

func TestFamilyIDsResolveToTheirFamily(t *testing.T) {
	m := mustLoad(t, SOC2)
	e, ok := m.Lookup("auth.source.header")
	if !ok || e.None == "" {
		t.Errorf("auth.source.header resolved to %+v, %v; want the auth.source.* entry", e, ok)
	}
}

func TestAssessStates(t *testing.T) {
	m := mustLoad(t, SOC2)
	states := func(vs []Verdict) map[string]State {
		out := map[string]State{}
		for _, a := range m.Assess(vs) {
			out[a.ID] = a.State
		}
		return out
	}
	s := states([]Verdict{
		{ID: "net.tls.cert", Status: "fail", Evidence: []string{"req#3"}},
		{ID: "auth.unauthenticated_tools", Status: "pass"},
		{ID: "performance.ping", Status: "skip"},
	})
	if s["CC6.7"] != Failing || s["CC6.1"] != Evidenced || s["A1.1"] != NotAssessed || s["CC1.1"] != NotCovered {
		t.Errorf("states = %v", s)
	}
	if states([]Verdict{{ID: "catalog.baseline", Status: "warn"}})["CC8.1"] != Failing {
		t.Error("a warning must count against a criterion")
	}
}

// AC: SOC2-05
func TestBundleListsUncoverableCriteriaAsNotCovered(t *testing.T) {
	m := mustLoad(t, SOC2)
	b := m.Bundle([]Record{{Target: "https://mcp.example.com/mcp", RanAt: time.Now(), Digest: "abc", Verdicts: []Verdict{{ID: "net.tls", Status: "pass"}}}}, time.Time{}, time.Time{})
	var cc11 *BundleCriterion
	for i := range b.Criteria {
		if b.Criteria[i].ID == "CC1.1" {
			cc11 = &b.Criteria[i]
		}
		if b.Criteria[i].State == Evidenced && b.Criteria[i].Reason != "" {
			t.Errorf("%s is evidenced and says it cannot be", b.Criteria[i].ID)
		}
	}
	if cc11 == nil || cc11.State != NotCovered || !strings.Contains(cc11.Reason, "organisational") {
		t.Fatalf("CC1.1 = %+v, want not covered by passmcp with its reason", cc11)
	}
	var csvOut bytes.Buffer
	if err := b.WriteCSV(&csvOut); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(csvOut.String(), "CC1.1,Commitment to integrity and ethical values,not covered by passmcp") {
		t.Errorf("the CSV does not list CC1.1 as not covered:\n%s", csvOut.String())
	}
}

// AC: ISO-06
func TestBundleShowsEachDateAndMarksARegression(t *testing.T) {
	m := mustLoad(t, ISO27001)
	t1 := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	t2 := t1.AddDate(0, 3, 0)
	target := "https://mcp.example.com/mcp"
	b := m.Bundle([]Record{
		{Target: target, RanAt: t2, Digest: "later", Verdicts: []Verdict{{ID: "net.tls.cert", Status: "fail", Evidence: []string{"req#2"}}}},
		{Target: target, RanAt: t1, Digest: "earlier", Verdicts: []Verdict{{ID: "net.tls.cert", Status: "pass", Evidence: []string{"req#2"}}}},
	}, time.Time{}, time.Time{})
	var a824 BundleCriterion
	for _, c := range b.Criteria {
		if c.ID == "A.8.24" {
			a824 = c
		}
	}
	if len(a824.Observations) != 2 {
		t.Fatalf("A.8.24 has %d observations, want one per date", len(a824.Observations))
	}
	first, second := a824.Observations[0], a824.Observations[1]
	if !first.RanAt.Equal(t1) || first.State != Evidenced || first.Digest != "earlier" {
		t.Errorf("first observation = %+v", first)
	}
	if !second.RanAt.Equal(t2) || second.State != Failing || !second.Regressed || !a824.Regressed {
		t.Errorf("second observation = %+v, criterion regressed = %v", second, a824.Regressed)
	}
	if a824.State != Failing {
		t.Errorf("the criterion's state is %s; the latest attestation fails it", a824.State)
	}
}

func TestBundleKeepsOnlyThePeriod(t *testing.T) {
	m := mustLoad(t, SOC2)
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	recs := []Record{
		{Target: "x", RanAt: t1, Digest: "early"},
		{Target: "x", RanAt: t1.AddDate(0, 6, 0), Digest: "inside", Verdicts: []Verdict{{ID: "net.tls", Status: "pass"}}},
		{Target: "x", RanAt: t1.AddDate(1, 0, 0), Digest: "late"},
	}
	b := m.Bundle(recs, t1.AddDate(0, 1, 0), t1.AddDate(0, 11, 0))
	for _, c := range b.Criteria {
		for _, o := range c.Observations {
			if o.Digest != "inside" {
				t.Fatalf("%s has an observation from outside the period: %+v", c.ID, o)
			}
		}
	}
	if b.From == nil || b.To == nil || len(b.Targets) != 1 {
		t.Errorf("bundle period or targets wrong: %+v %+v %v", b.From, b.To, b.Targets)
	}
}

func TestParseFramework(t *testing.T) {
	for in, want := range map[string]Framework{"SOC2": SOC2, " iso27001 ": ISO27001, "gdpr": GDPR} {
		if got, err := ParseFramework(in); err != nil || got != want {
			t.Errorf("ParseFramework(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseFramework("pci"); err == nil {
		t.Error("an unknown framework must be refused")
	}
	if _, err := Load("pci"); err == nil {
		t.Error("Load must refuse an unknown framework")
	}
}

func TestMarkdownListsEveryCriterionAndCheck(t *testing.T) {
	m := mustLoad(t, GDPR)
	var b bytes.Buffer
	if err := m.Markdown(&b); err != nil {
		t.Fatal(err)
	}
	page := b.String()
	for _, c := range m.Criteria {
		if !strings.Contains(page, "| "+c.ID+" |") {
			t.Errorf("the page does not list %s", c.ID)
		}
	}
	if !strings.Contains(page, "`catalog.personal_data`") {
		t.Error("the page does not list catalog.personal_data")
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
