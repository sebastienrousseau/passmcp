// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// day is a fixed clock. An expiry that cannot be tested at a known date is an
// expiry nobody tests, which is why Evaluate takes the time.
var day = time.Date(2027, 3, 15, 0, 0, 0, 0, time.UTC)

func ptr[T any](v T) *T { return &v }

// sample is a subject with one of everything a rule can read.
func sample() Subject {
	return Subject{
		Transport: "http",
		Endpoint:  "https://mcp.example.com/mcp",
		Verdicts: []Verdict{
			{ID: "net.dns", Status: "pass"},
			{ID: "net.tls", Status: "pass"},
			{ID: "auth.unauthenticated_tools", Status: "fail", Severity: Critical},
			{ID: "catalog.tools.annotations", Status: "warn", Severity: Minor},
			{ID: "protocol.id_echo", Status: "fail", Severity: Major},
			{ID: "perf.latency", Status: "skip"},
		},
		Counts: Counts{Pass: 2, Warn: 1, Fail: 2, Skip: 1},
		Score: &Score{
			Total:      64.5,
			Categories: map[string]float64{"authorization": 40, "connectivity": 100, "protocol": 60},
		},
	}
}

func minimal() *Policy { return &Policy{Version: 1, Name: "test"} }

// A policy with no rule judges nothing, and must not be mistaken for a pass
// it earned. Validate allows it — a team may want the reporting before the
// gating — so Rules is how a caller can tell.
func TestAPolicyWithNoRuleJudgesNothing(t *testing.T) {
	p := minimal()
	if err := p.Validate(); err != nil {
		t.Fatalf("an empty policy is a legitimate starting point: %v", err)
	}
	if p.Rules() != 0 {
		t.Errorf("Rules() = %d for a policy with no rules", p.Rules())
	}
	res := p.Evaluate(sample(), day)
	if !res.OK || len(res.Rules) != 0 {
		t.Errorf("result = %+v", res)
	}
}

func TestMustPass(t *testing.T) {
	cases := map[string]struct {
		check    string
		met      bool
		mentions string
	}{
		"a check that passed": {"net.dns", true, "passed"},
		"a check that failed": {"protocol.id_echo", false, "fail (major)"},
		"a check that warned": {"catalog.tools.annotations", false, "warn"},
		// Absent is not a pass. A run that never made the check cannot vouch
		// for it, and reading silence as success is how a gate becomes
		// decoration.
		"a check that did not run": {"execution.tools_callable", false, "did not run"},
		// A skip is not a pass either, and for the same reason.
		"a check that was skipped": {"perf.latency", false, "skip"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := minimal()
			p.MustPass = []string{tc.check}
			res := p.Evaluate(sample(), day)
			if res.OK != tc.met {
				t.Fatalf("OK = %v, want %v: %+v", res.OK, tc.met, res.Rules)
			}
			if len(res.Rules) != 1 {
				t.Fatalf("%d rules reported for one rule", len(res.Rules))
			}
			if !strings.Contains(res.Rules[0].Detail, tc.mentions) {
				t.Errorf("detail %q does not mention %q", res.Rules[0].Detail, tc.mentions)
			}
		})
	}
}

// must_not_fail is the weaker form, for a check where a warning is tolerable.
// It has to be genuinely weaker, or there is no reason for it to exist.
func TestMustNotFailToleratesAWarning(t *testing.T) {
	p := minimal()
	p.MustNotFail = []string{"catalog.tools.annotations"}
	if res := p.Evaluate(sample(), day); !res.OK {
		t.Errorf("a warning failed must_not_fail: %+v", res.Rules)
	}

	p = minimal()
	p.MustNotFail = []string{"protocol.id_echo"}
	if res := p.Evaluate(sample(), day); res.OK {
		t.Error("a failure passed must_not_fail")
	}

	// And absence is still not tolerable: nothing says the check did not fail.
	p = minimal()
	p.MustNotFail = []string{"nothing.ran"}
	res := p.Evaluate(sample(), day)
	if res.OK || !strings.Contains(res.Rules[0].Detail, "did not run") {
		t.Errorf("an absent check satisfied must_not_fail: %+v", res.Rules)
	}
}

func TestCountAndScoreRules(t *testing.T) {
	t.Run("max_fail", func(t *testing.T) {
		p := minimal()
		p.MaxFail = ptr(2)
		if res := p.Evaluate(sample(), day); !res.OK {
			t.Errorf("2 failures did not meet max_fail 2: %+v", res.Rules)
		}
		p.MaxFail = ptr(1)
		if res := p.Evaluate(sample(), day); res.OK {
			t.Error("2 failures met max_fail 1")
		}
		// Zero is a rule, not a sentinel.
		p.MaxFail = ptr(0)
		res := p.Evaluate(sample(), day)
		if res.OK || len(res.Rules) != 1 {
			t.Errorf("max_fail 0 was not applied: %+v", res.Rules)
		}
	})

	t.Run("max_warn counts warnings, not failures", func(t *testing.T) {
		p := minimal()
		p.MaxWarn = ptr(0)
		res := p.Evaluate(sample(), day)
		if res.OK {
			t.Error("one warning met max_warn 0")
		}
		if !strings.Contains(res.Rules[0].Detail, "1 check warned") {
			t.Errorf("max_warn counted the wrong thing: %q", res.Rules[0].Detail)
		}
	})

	t.Run("min_score", func(t *testing.T) {
		p := minimal()
		p.MinScore = ptr(64.5)
		if res := p.Evaluate(sample(), day); !res.OK {
			t.Errorf("64.5 did not meet min_score 64.5: %+v", res.Rules)
		}
		p.MinScore = ptr(65.0)
		if res := p.Evaluate(sample(), day); res.OK {
			t.Error("64.5 met min_score 65")
		}
	})

	// A run that assessed nothing carries no score, and the statement says so
	// by omitting it. Reading a missing score as zero would fail a server for
	// something that is a fact about the run.
	t.Run("a subject with no score", func(t *testing.T) {
		s := sample()
		s.Score = nil
		p := minimal()
		p.MinScore = ptr(0.0)
		res := p.Evaluate(s, day)
		if res.OK {
			t.Error("a missing score met min_score 0, so it was read as zero")
		}
		if !strings.Contains(res.Rules[0].Detail, "no category") {
			t.Errorf("detail does not explain why: %q", res.Rules[0].Detail)
		}
	})

	t.Run("min_category_score", func(t *testing.T) {
		p := minimal()
		p.MinCategoryScore = map[string]float64{"connectivity": 90}
		if res := p.Evaluate(sample(), day); !res.OK {
			t.Errorf("connectivity 100 did not meet 90: %+v", res.Rules)
		}
		p.MinCategoryScore = map[string]float64{"authorization": 90}
		if res := p.Evaluate(sample(), day); res.OK {
			t.Error("authorization 40 met 90")
		}
		// A category the run did not assess cannot meet a minimum, and must
		// not be treated as zero or as absent-therefore-fine.
		p.MinCategoryScore = map[string]float64{"execution": 1}
		res := p.Evaluate(sample(), day)
		if res.OK || !strings.Contains(res.Rules[0].Detail, "not assessed") {
			t.Errorf("an unassessed category was judged anyway: %+v", res.Rules)
		}
	})
}

// forbid_severity is a threshold, so forbidding major forbids critical too.
// Getting that backwards would let the worst failures through.
func TestForbidSeverityIsAThreshold(t *testing.T) {
	cases := map[string]struct {
		forbid Severity
		met    bool
		names  []string
	}{
		"critical forbids only critical": {Critical, false, []string{"auth.unauthenticated_tools"}},
		"major forbids critical too":     {Major, false, []string{"auth.unauthenticated_tools", "protocol.id_echo"}},
		"minor forbids all three":        {Minor, false, []string{"auth.unauthenticated_tools", "protocol.id_echo"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := minimal()
			p.ForbidSeverity = tc.forbid
			res := p.Evaluate(sample(), day)
			if res.OK != tc.met {
				t.Fatalf("OK = %v: %+v", res.OK, res.Rules)
			}
			for _, want := range tc.names {
				if !strings.Contains(res.Rules[0].Detail, want) {
					t.Errorf("detail does not name %s: %q", want, res.Rules[0].Detail)
				}
			}
		})
	}

	// Only failures count. A warning carries a severity too, and treating it
	// as forbidden would make forbid_severity: minor refuse every server with
	// any warning at all.
	t.Run("a warning is not a forbidden failure", func(t *testing.T) {
		s := Subject{Verdicts: []Verdict{{ID: "a", Status: "warn", Severity: Critical}}}
		p := minimal()
		p.ForbidSeverity = Critical
		if res := p.Evaluate(s, day); !res.OK {
			t.Errorf("a warning tripped forbid_severity: %+v", res.Rules)
		}
	})
}

func TestTargetRule(t *testing.T) {
	p := minimal()
	p.Target = &Target{Transport: "http", Endpoint: "https://mcp.example.com/mcp"}
	if res := p.Evaluate(sample(), day); !res.OK {
		t.Errorf("the matching target was refused: %+v", res.Rules)
	}

	p.Target = &Target{Transport: "stdio"}
	res := p.Evaluate(sample(), day)
	if res.OK || !strings.Contains(res.Rules[0].Detail, "not written for this server") {
		t.Errorf("a stdio policy was applied to an http server: %+v", res.Rules)
	}

	p.Target = &Target{Endpoint: "https://other.example.com/mcp"}
	if res := p.Evaluate(sample(), day); res.OK {
		t.Error("a policy for another endpoint was met")
	}
}

func TestExemptions(t *testing.T) {
	base := func(e Exemption) *Policy {
		p := minimal()
		p.MaxFail = ptr(1)
		p.ForbidSeverity = Critical
		p.Exemptions = []Exemption{e}
		return p
	}

	// The whole reason exemptions exist: without one, two failures and a
	// critical mean no. With one, the team's written decision carries.
	t.Run("an applied exemption excuses the failure", func(t *testing.T) {
		p := base(Exemption{
			Check: "auth.unauthenticated_tools", Reason: "internal network only, behind the mesh",
			Expires: Date{time.Date(2027, 6, 30, 0, 0, 0, 0, time.UTC)}, Ticket: "SEC-4411",
		})
		res := p.Evaluate(sample(), day)
		if !res.OK {
			t.Fatalf("the exemption did not apply: %+v", res.Rules)
		}
		if len(res.Exemptions) != 1 || !res.Exemptions[0].Applied {
			t.Fatalf("exemptions = %+v", res.Exemptions)
		}
		// The pass must never be silent about how it was reached.
		var counted string
		for _, r := range res.Rules {
			if r.Rule == "max_fail" {
				counted = r.Detail
			}
		}
		if !strings.Contains(counted, "1 exempted") {
			t.Errorf("max_fail did not say a failure was excused: %q", counted)
		}
	})

	// An expired exemption is a failure about the decision, not about the
	// server, and the wording has to say so — the reader's next action is to
	// renew it or fix the check.
	t.Run("an expired exemption fails and says why", func(t *testing.T) {
		p := base(Exemption{
			Check: "auth.unauthenticated_tools", Reason: "internal network only",
			Expires: Date{time.Date(2027, 3, 14, 0, 0, 0, 0, time.UTC)},
		})
		res := p.Evaluate(sample(), day)
		if res.OK {
			t.Fatal("an expired exemption still excused a critical failure")
		}
		if !res.Exemptions[0].Expired {
			t.Errorf("exemption = %+v", res.Exemptions[0])
		}
		var detail string
		for _, r := range res.Rules {
			if r.Rule == "exemption:auth.unauthenticated_tools" {
				detail = r.Detail
			}
		}
		for _, want := range []string{"expired on 2027-03-14", "is still fail"} {
			if !strings.Contains(detail, want) {
				t.Errorf("detail %q does not contain %q", detail, want)
			}
		}
	})

	// The expiry day itself is still covered: "expires 2027-03-31" reads as
	// "good through the 31st", which is what everybody means by it.
	t.Run("the expiry day is still covered", func(t *testing.T) {
		p := base(Exemption{
			Check: "auth.unauthenticated_tools", Reason: "r",
			Expires: Date{day},
		})
		if res := p.Evaluate(sample(), day); !res.OK {
			t.Errorf("an exemption expiring today did not cover today: %+v", res.Rules)
		}
	})

	// An exemption nobody needs is how one retires. Not a failure, and it has
	// to be visible or the file fills with excuses for problems long fixed.
	t.Run("an unused exemption is reported, not failed", func(t *testing.T) {
		p := minimal()
		p.Exemptions = []Exemption{{
			Check: "net.dns", Reason: "was flaky in the old datacentre",
			Expires: Date{time.Date(2027, 12, 31, 0, 0, 0, 0, time.UTC)},
		}}
		res := p.Evaluate(sample(), day)
		if !res.OK {
			t.Fatalf("an unused exemption failed the policy: %+v", res.Rules)
		}
		e := res.Exemptions[0]
		if !e.Unused || e.Applied {
			t.Errorf("exemption = %+v", e)
		}
		if e.Status != "pass" {
			t.Errorf("the reader is not told the check now passes: %+v", e)
		}
	})

	// An exemption for a check that never ran is also unused, and the two
	// have to be distinguishable: one means "fixed", the other means "not
	// measured", and only the first justifies deleting it.
	t.Run("an exemption for a check that did not run", func(t *testing.T) {
		p := minimal()
		p.Exemptions = []Exemption{{
			Check: "execution.tools_callable", Reason: "execution phase is skipped here",
			Expires: Date{time.Date(2027, 12, 31, 0, 0, 0, 0, time.UTC)},
		}}
		res := p.Evaluate(sample(), day)
		if !res.OK {
			t.Fatalf("OK = false: %+v", res.Rules)
		}
		if e := res.Exemptions[0]; !e.Unused || e.Status != "" {
			t.Errorf("exemption = %+v, want unused with no status", e)
		}
	})

	// A warning can be exempted too, so max_warn is usable on a fleet where
	// one server has a known, accepted deviation.
	t.Run("a warning can be exempted", func(t *testing.T) {
		p := minimal()
		p.MaxWarn = ptr(0)
		p.Exemptions = []Exemption{{
			Check: "catalog.tools.annotations", Reason: "vendor will annotate in the next release",
			Expires: Date{time.Date(2027, 9, 30, 0, 0, 0, 0, time.UTC)},
		}}
		if res := p.Evaluate(sample(), day); !res.OK {
			t.Errorf("an exempted warning still tripped max_warn 0: %+v", res.Rules)
		}
	})
}

func TestValidateRefuses(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Policy)
		want   string
	}{
		"no version": {func(p *Policy) { p.Version = 0 }, "no version"},
		// The one property worth being inflexible about: a policy engine
		// that ignores what it does not understand approves things.
		"a later version":    {func(p *Policy) { p.Version = Version + 1 }, "upgrade passmcp"},
		"a negative version": {func(p *Policy) { p.Version = -1 }, "not a version"},
		"no name":            {func(p *Policy) { p.Name = "" }, "no name"},
		"an unknown transport": {
			func(p *Policy) { p.Target = &Target{Transport: "carrier-pigeon"} }, "neither http nor stdio"},
		"an empty target block": {func(p *Policy) { p.Target = &Target{} }, "constrains nothing"},
		"an unknown severity": {
			func(p *Policy) { p.ForbidSeverity = "annoying" }, "not critical, major or minor"},
		"a negative allowance": {func(p *Policy) { p.MaxFail = ptr(-1) }, "cannot be met by any run"},
		"a score above 100":    {func(p *Policy) { p.MinScore = ptr(101.0) }, "0 to 100"},
		"a category score above 100": {
			func(p *Policy) { p.MinCategoryScore = map[string]float64{"auth": 101} }, "0 to 100"},
		"an unnamed category": {
			func(p *Policy) { p.MinCategoryScore = map[string]float64{" ": 10} }, "no category name"},
		"an exemption with no check":  {func(p *Policy) { p.Exemptions = []Exemption{{Reason: "r", Expires: Date{day}}} }, "names no check"},
		"an exemption with no reason": {func(p *Policy) { p.Exemptions = []Exemption{{Check: "a", Expires: Date{day}}} }, "no reason"},
		// The difference between an exception and a hole is the date.
		"an exemption with no expiry": {func(p *Policy) { p.Exemptions = []Exemption{{Check: "a", Reason: "r"}} }, "permanent hole"},
		"an exemption twice": {func(p *Policy) {
			p.Exemptions = []Exemption{
				{Check: "a", Reason: "r", Expires: Date{day}},
				{Check: "a", Reason: "other", Expires: Date{day}},
			}
		}, "exempted twice"},
		// Both required and exempted has two answers, and whichever passmcp
		// picked would surprise half its readers.
		"required and exempted": {func(p *Policy) {
			p.MustPass = []string{"a"}
			p.Exemptions = []Exemption{{Check: "a", Reason: "r", Expires: Date{day}}}
		}, "both required and exempted"},
		"a check required twice": {func(p *Policy) { p.MustPass = []string{"a", "a"} }, "names a twice"},
		"an empty check id":      {func(p *Policy) { p.MustNotFail = []string{" "} }, "empty check id"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := minimal()
			tc.mutate(p)
			err := p.Validate()
			if err == nil {
				t.Fatalf("accepted %s", name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error does not mention %q: %v", tc.want, err)
			}
		})
	}
}

// A misspelled rule name would otherwise be a rule that silently does not
// apply, which is the worst failure mode a gate has: it reports success.
func TestParseRefusesAnUnknownField(t *testing.T) {
	_, err := Parse([]byte(`{"version":1,"name":"p","must_pas":["net.dns"]}`))
	if err == nil {
		t.Fatal("a misspelled rule was accepted, so it would have been silently ignored")
	}
	if !strings.Contains(err.Error(), "must_pas") {
		t.Errorf("the error does not name the field: %v", err)
	}
}

func TestDateForm(t *testing.T) {
	var d Date
	if err := json.Unmarshal([]byte(`"2027-03-31"`), &d); err != nil {
		t.Fatal(err)
	}
	if d.String() != "2027-03-31" {
		t.Errorf("date = %s", d)
	}
	b, err := json.Marshal(d)
	if err != nil || string(b) != `"2027-03-31"` {
		t.Errorf("marshal = %s, %v", b, err)
	}
	// A timestamp is refused rather than truncated: an expiry with a clock
	// time in it passes in one timezone and fails in another.
	for _, bad := range []string{`"2027-03-31T12:00:00Z"`, `"31/03/2027"`, `"March"`, `1234`} {
		if err := json.Unmarshal([]byte(bad), &d); err == nil {
			t.Errorf("%s was accepted as a date", bad)
		}
	}
	// Empty is the zero date, which Validate refuses with its own message.
	if err := json.Unmarshal([]byte(`""`), &d); err != nil || !d.IsZero() {
		t.Errorf("empty date: %v, zero=%v", err, d.IsZero())
	}
	if d.String() != "never" {
		t.Errorf("the zero date renders as %q", d)
	}
}

func TestLoadFromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	body := `{
  "version": 1,
  "name": "platform baseline",
  "description": "what we route to",
  "must_pass": ["net.tls"],
  "max_fail": 0,
  "min_score": 70,
  "forbid_severity": "major",
  "exemptions": [
    {"check": "auth.unauthenticated_tools", "reason": "mesh-internal", "expires": "2027-06-30", "ticket": "SEC-4411"}
  ]
}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "platform baseline" || p.Rules() != 4 {
		t.Errorf("policy = %+v, rules = %d", p, p.Rules())
	}
	res := p.Evaluate(sample(), day)
	// min_score 70 against 64.5, so this must not pass — and the exemption
	// must not be mistaken for a blanket excuse.
	if res.OK {
		t.Errorf("the policy was met despite a score below its minimum: %+v", res.Rules)
	}
	if _, err := Load(filepath.Join(dir, "nope.json")); err == nil {
		t.Error("a missing policy file loaded")
	}
}

// An expired exemption's message has to tell the reader what to do, and the
// three cases call for different actions: renew it, delete it, or look at why
// the check stopped running. Only the first was covered by the cases above.
func TestAnExpiredExemptionSaysWhatToDo(t *testing.T) {
	yesterday := Date{day.AddDate(0, 0, -1)}
	cases := map[string]struct {
		check string
		want  string
	}{
		"the check now passes":  {"net.dns", "can be removed rather than renewed"},
		"the check did not run": {"execution.tools_callable", "did not run"},
		"the check still fails": {"protocol.id_echo", "is still fail (major)"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := minimal()
			p.Exemptions = []Exemption{{Check: tc.check, Reason: "r", Expires: yesterday}}
			res := p.Evaluate(sample(), day)
			if res.OK {
				t.Fatal("an expired exemption did not fail the policy")
			}
			if !strings.Contains(res.Rules[0].Detail, tc.want) {
				t.Errorf("detail %q does not contain %q", res.Rules[0].Detail, tc.want)
			}
		})
	}
}

// An exemption with no expiry is refused by Validate, but Evaluate must not
// depend on that having happened: a Policy built in Go rather than loaded from
// a file reaches Evaluate directly, and a zero date has to mean expired rather
// than "forever".
func TestAZeroExpiryIsExpiredNotForever(t *testing.T) {
	p := minimal()
	p.Exemptions = []Exemption{{Check: "auth.unauthenticated_tools", Reason: "r"}}
	res := p.Evaluate(sample(), day)
	if res.OK {
		t.Fatal("an exemption with no expiry excused a failure")
	}
	if !res.Exemptions[0].Expired {
		t.Errorf("exemption = %+v", res.Exemptions[0])
	}
	if !strings.Contains(res.Rules[0].Detail, "never") {
		t.Errorf("detail does not say the expiry was absent: %q", res.Rules[0].Detail)
	}
	// And it round-trips as an empty string rather than a year-one date,
	// which is what a policy read back out of a report would otherwise show.
	b, err := json.Marshal(Date{})
	if err != nil || string(b) != `""` {
		t.Errorf("the zero date marshals as %s, %v", b, err)
	}
}

// Parse validates as well as decodes. A file that reads cleanly and states an
// impossible rule must be refused at load, not at evaluation.
func TestParseValidatesToo(t *testing.T) {
	_, err := Parse([]byte(`{"version":1,"name":"p","max_fail":-3}`))
	if err == nil {
		t.Fatal("a policy with a negative allowance parsed")
	}
	if !strings.Contains(err.Error(), "cannot be met by any run") {
		t.Errorf("error = %v", err)
	}
}
