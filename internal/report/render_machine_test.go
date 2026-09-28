// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"sort"
	"strings"
	"testing"
)

// TestSARIFShape asserts the parts a consumer actually indexes on.
//
// These are not cosmetic: GitHub code scanning keys alerts on ruleId and
// partialFingerprints, resolves ruleIndex into the rules array, and drops a
// result whose level it does not recognise.
func TestSARIFShape(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, fullReport(), "1.2.3"); err != nil {
		t.Fatalf("SARIF: %v", err)
	}

	var doc struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Rules   []struct {
						ID      string `json:"id"`
						Name    string `json:"name"`
						HelpURI string `json:"helpUri"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			AutomationDetails struct {
				ID string `json:"id"`
			} `json:"automationDetails"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Kind      string `json:"kind"`
				Level     string `json:"level"`
				Message   struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v\n%s", err, buf.String())
	}

	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", doc.Version)
	}
	if !strings.Contains(doc.Schema, "sarif-schema-2.1.0") {
		t.Errorf("$schema = %q, which does not name the 2.1.0 schema", doc.Schema)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "passmcp" || run.Tool.Driver.Version != "1.2.3" {
		t.Errorf("driver = %q %q", run.Tool.Driver.Name, run.Tool.Driver.Version)
	}
	if run.AutomationDetails.ID != "abc" {
		t.Errorf("automationDetails.id = %q, want the run's trace id", run.AutomationDetails.ID)
	}

	// Every finding in the fixture is reported, passes included: a consumer
	// must be able to tell "checked and fine" from "not checked".
	if got, want := len(run.Results), countFindings(fullReport()); got != want {
		t.Errorf("results = %d, want %d (one per finding, passes included)", got, want)
	}

	levels := map[string]string{}
	kinds := map[string]string{}
	for _, res := range run.Results {
		levels[res.RuleID] = res.Level
		kinds[res.RuleID] = res.Kind

		// ruleIndex must resolve, or the consumer shows a result with no
		// rule behind it.
		if res.RuleIndex < 0 || res.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Errorf("%s: ruleIndex %d out of range", res.RuleID, res.RuleIndex)
			continue
		}
		if got := run.Tool.Driver.Rules[res.RuleIndex].ID; got != res.RuleID {
			t.Errorf("%s: ruleIndex %d points at rule %q", res.RuleID, res.RuleIndex, got)
		}
		if len(res.Locations) == 0 {
			t.Errorf("%s: no location; consumers drop a result without one", res.RuleID)
			continue
		}
		if got := res.Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "https://x/mcp" {
			t.Errorf("%s: location = %q, want the endpoint under test", res.RuleID, got)
		}
		if res.PartialFingerprints["passmcpCheckId/v1"] == "" {
			t.Errorf("%s: no fingerprint; every run would open a new alert", res.RuleID)
		}
	}

	for _, tc := range []struct{ id, kind, level string }{
		{"p.crit", "fail", "error"},
		{"p.minor", "fail", "warning"},
		{"p.warn", "review", "warning"},
		{"net.a", "pass", "none"},
		{"net.i", "informational", "note"},
		{"p.skip", "notApplicable", "none"},
	} {
		if kinds[tc.id] != tc.kind || levels[tc.id] != tc.level {
			t.Errorf("%s: kind/level = %q/%q, want %q/%q",
				tc.id, kinds[tc.id], levels[tc.id], tc.kind, tc.level)
		}
	}
}

// TestSARIFRulesAreStable guards against the map iteration order that
// produced rules in a different order on every run. A report format that
// reorders itself makes a diff between two identical runs unreadable.
func TestSARIFRulesAreStable(t *testing.T) {
	first := sarifRuleIDs(t)
	for range 20 {
		if got := sarifRuleIDs(t); !equal(got, first) {
			t.Fatalf("rule order changed between runs:\n%v\n%v", first, got)
		}
	}
	if !sort.StringsAreSorted(first) {
		t.Errorf("rules are not sorted: %v", first)
	}
}

func sarifRuleIDs(t *testing.T) []string {
	t.Helper()
	var buf bytes.Buffer
	if err := SARIF(&buf, fullReport(), "t"); err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	ids := make([]string, 0, len(doc.Runs[0].Tool.Driver.Rules))
	for _, r := range doc.Runs[0].Tool.Driver.Rules {
		ids = append(ids, r.ID)
	}
	return ids
}

// TestJUnitShape asserts what a CI system reads: the counts in the
// attributes, one testcase per finding, and a warning that is visible
// rather than quietly folded into the passes.
// Named rather than anonymous so a helper can walk the result.
type juFailure struct {
	Type    string `xml:"type,attr"`
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

type juSkipped struct {
	Message string `xml:"message,attr"`
}

type juCase struct {
	Name      string     `xml:"name,attr"`
	ClassName string     `xml:"classname,attr"`
	Failure   *juFailure `xml:"failure"`
	Skipped   *juSkipped `xml:"skipped"`
}

type juSuite struct {
	Name  string   `xml:"name,attr"`
	Cases []juCase `xml:"testcase"`
}

type juSuites struct {
	XMLName  xml.Name  `xml:"testsuites"`
	Tests    int       `xml:"tests,attr"`
	Failures int       `xml:"failures,attr"`
	Skipped  int       `xml:"skipped,attr"`
	Suites   []juSuite `xml:"testsuite"`
}

func findCase(suites []juSuite, name string) *juCase {
	for i := range suites {
		for j := range suites[i].Cases {
			if suites[i].Cases[j].Name == name {
				return &suites[i].Cases[j]
			}
		}
	}
	return nil
}

// TestJUnitShape asserts what a CI system reads: the counts in the
// attributes, one testcase per finding, and a warning that is visible
// rather than quietly folded into the passes.
func TestJUnitShape(t *testing.T) {
	var buf bytes.Buffer
	if err := JUnit(&buf, fullReport()); err != nil {
		t.Fatalf("JUnit: %v", err)
	}
	if !strings.HasPrefix(buf.String(), xml.Header) {
		t.Error("no XML declaration; some readers refuse the file")
	}

	var suites juSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("JUnit is not well-formed XML: %v\n%s", err, buf.String())
	}

	cases := map[string]int{}
	var failures, skipped int
	for _, s := range suites.Suites {
		if !strings.HasPrefix(s.Name, "passmcp.") {
			t.Errorf("suite %q is not namespaced", s.Name)
		}
		for _, c := range s.Cases {
			cases[c.Name]++
			if c.Failure != nil {
				failures++
			}
			if c.Skipped != nil {
				skipped++
			}
		}
	}

	// A warning is a failure with a type that says so. Folding it into the
	// passes is how a deviation stops being read.
	for id, wantType := range map[string]string{
		"p.crit":  "critical",
		"p.minor": "minor",
		"p.warn":  "warning",
	} {
		c := findCase(suites.Suites, id)
		if c == nil || c.Failure == nil {
			t.Errorf("%s: expected a <failure>", id)
			continue
		}
		if c.Failure.Type != wantType {
			t.Errorf("%s: failure type = %q, want %q", id, c.Failure.Type, wantType)
		}
		if c.Failure.Message == "" {
			t.Errorf("%s: empty failure message; that is the line CI shows", id)
		}
	}

	// The phase that never ran is still present. A suite that vanishes
	// reads as a phase that passed.
	if c := findCase(suites.Suites, "auth"); c == nil || c.Skipped == nil {
		t.Error("the skipped auth phase produced no skipped testcase")
	}

	if failures != suites.Failures {
		t.Errorf("failures attribute = %d, counted %d", suites.Failures, failures)
	}
	if skipped != suites.Skipped {
		t.Errorf("skipped attribute = %d, counted %d", suites.Skipped, skipped)
	}
	for id, n := range cases {
		if n != 1 {
			t.Errorf("%s appears %d times; a CI system keys history on the name", id, n)
		}
	}
}

// TestMachineFormatsTolerateNil is the shape every other renderer here
// already has: a nil report is a run that produced nothing, not a panic.
func TestMachineFormatsTolerateNil(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, nil, "t"); err != nil || buf.Len() != 0 {
		t.Errorf("SARIF(nil) = %v, wrote %d bytes", err, buf.Len())
	}
	if err := JUnit(&buf, nil); err != nil || buf.Len() != 0 {
		t.Errorf("JUnit(nil) = %v, wrote %d bytes", err, buf.Len())
	}
}

func countFindings(r *Report) int {
	n := 0
	for _, p := range r.Phases {
		n += len(p.Findings)
	}
	return n
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestSARIFLocatesAStdioTarget: the two machine formats identify a target,
// and over stdio there is no host and no URL to identify it with.
//
// The fingerprint is the part that matters. It is what lets a consumer track
// one alert across nightly runs instead of opening a new one each time — and
// it was built from Target.Host, which is empty for every stdio run. Two
// different servers on one machine would have produced identical
// fingerprints and merged into one alert.
func TestSARIFLocatesAStdioTarget(t *testing.T) {
	mk := func(cmd ...string) *Report {
		r := guidedReport()
		r.Target = Target{
			Endpoint:  strings.Join(cmd, " "),
			Scheme:    "stdio",
			Transport: "stdio",
			Command:   cmd,
		}
		return r
	}

	var a, b bytes.Buffer
	if err := SARIF(&a, mk("npx", "-y", "server-one"), "t"); err != nil {
		t.Fatal(err)
	}
	if err := SARIF(&b, mk("npx", "-y", "server-two"), "t"); err != nil {
		t.Fatal(err)
	}

	var doc struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(a.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if len(doc.Runs) == 0 || len(doc.Runs[0].Results) == 0 {
		t.Fatal("no results")
	}
	res := doc.Runs[0].Results[0]

	uri := res.Locations[0].PhysicalLocation.ArtifactLocation.URI
	if !strings.HasPrefix(uri, "stdio:") {
		t.Errorf("artifact URI %q does not say what kind of location it is", uri)
	}
	if strings.ContainsAny(uri, " ") {
		t.Errorf("artifact URI %q contains a space, so it is not a URI", uri)
	}

	fp := res.PartialFingerprints["passmcpCheckId/v1"]
	if strings.HasSuffix(fp, "@") {
		t.Errorf("fingerprint %q identifies no target; every stdio run would share it", fp)
	}

	// And the two servers must not collide.
	var other struct {
		Runs []struct {
			Results []struct {
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b.Bytes(), &other); err != nil {
		t.Fatal(err)
	}
	if got := other.Runs[0].Results[0].PartialFingerprints["passmcpCheckId/v1"]; got == fp {
		t.Errorf("two different stdio servers produced the same fingerprint %q", got)
	}
}
