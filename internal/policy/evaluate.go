// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package policy

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"satellion.com/passmcp/internal/attest"
	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/report"
)

// Subject is what a policy judges.
//
// Its own shape rather than a report or a statement, because the same policy
// has to mean the same thing applied to either — a live run and the signed
// claim derived from it must not be able to reach different verdicts. Anything
// a rule reads is in here, and the two adapters below are the only places
// that know the difference.
type Subject struct {
	Transport string
	Endpoint  string
	Verdicts  []Verdict
	Counts    Counts
	// Score is nil when the run assessed no category, which is a different
	// thing from a score of zero.
	Score *Score
}

// Verdict is one check's outcome, reduced to what a rule can read.
type Verdict struct {
	ID       string
	Status   string
	Severity Severity
}

// Counts totals the verdicts by status.
type Counts struct{ Pass, Warn, Fail, Skip, Info int }

// Score is the rating and its per-category derivation.
type Score struct {
	Total float64
	// Categories holds only the categories the run actually assessed. A
	// category that did not run is absent rather than zero.
	Categories map[string]float64
}

// FromReport builds a subject from a finished run.
func FromReport(r *report.Report) Subject {
	s := Subject{
		Transport: transportOf(r),
		Endpoint:  r.Target.Endpoint,
		Counts: Counts{
			Pass: r.Counts.Pass, Warn: r.Counts.Warn,
			Fail: r.Counts.Fail, Skip: r.Counts.Skip, Info: r.Counts.Info,
		},
	}
	for _, ph := range r.Phases {
		for _, f := range ph.Findings {
			s.Verdicts = append(s.Verdicts, Verdict{
				ID: f.ID, Status: string(f.Status), Severity: Severity(f.Severity),
			})
		}
	}
	if r.Score.Assessed > 0 {
		sc := &Score{Total: r.Score.Total, Categories: map[string]float64{}}
		for _, c := range r.Score.Categories {
			if c.Assessed {
				sc.Categories[c.Name] = c.Score
			}
		}
		s.Score = sc
	}
	return s
}

// FromStatement builds a subject from an attestation.
//
// The point of this adapter is that a gateway holding a signed statement and
// a policy can reach the same answer the pipeline did, months later, without
// the server being reachable.
func FromStatement(st *attest.Statement) Subject {
	p := st.Predicate
	s := Subject{
		Transport: p.Target.Transport,
		Endpoint:  p.Target.Endpoint,
		Counts: Counts{
			Pass: p.Counts.Pass, Warn: p.Counts.Warn,
			Fail: p.Counts.Fail, Skip: p.Counts.Skip, Info: p.Counts.Info,
		},
	}
	for _, v := range p.Verdicts {
		s.Verdicts = append(s.Verdicts, Verdict{
			ID: v.ID, Status: v.Status, Severity: Severity(v.Severity),
		})
	}
	if p.Score != nil {
		sc := &Score{Total: p.Score.Total, Categories: map[string]float64{}}
		for name, v := range p.Score.By {
			sc.Categories[name] = v
		}
		s.Score = sc
	}
	return s
}

// transportOf reads the transport a report describes.
func transportOf(r *report.Report) string {
	if r.Target.Scheme == "stdio" {
		return "stdio"
	}
	return "http"
}

// Result is the policy's answer.
type Result struct {
	Policy string `json:"policy"`
	OK     bool   `json:"ok"`
	Target struct {
		Transport string `json:"transport"`
		Endpoint  string `json:"endpoint"`
	} `json:"target"`
	Rules      []RuleResult      `json:"rules"`
	Exemptions []ExemptionResult `json:"exemptions,omitempty"`
}

// RuleResult is one rule and whether the subject met it.
type RuleResult struct {
	Rule   string `json:"rule"`
	Met    bool   `json:"met"`
	Detail string `json:"detail"`
}

// ExemptionResult records what each exemption did, which is as much of the
// output as the rules are: an expired exemption and an exemption nobody needs
// are both things a reviewer has to see.
type ExemptionResult struct {
	Check   string `json:"check"`
	Reason  string `json:"reason"`
	Expires string `json:"expires"`
	Ticket  string `json:"ticket,omitempty"`
	// Applied means the exemption actually excused something.
	Applied bool `json:"applied"`
	// Expired means it no longer excuses anything, which fails the policy:
	// the decision ran out, and somebody has to make it again or fix the
	// server.
	Expired bool `json:"expired"`
	// Unused means the check it names did not fail. Not a failure — it is
	// how an exemption retires — but it has to be visible or the file fills
	// up with excuses for problems that were fixed years ago.
	Unused bool   `json:"unused"`
	Status string `json:"status,omitempty"`
}

// Evaluate applies the policy to the subject as of now.
//
// now is a parameter rather than time.Now() because an expiry that cannot be
// tested at a fixed date is an expiry nobody tests.
func (p *Policy) Evaluate(s Subject, now time.Time) Result {
	e := &evaluation{p: p, s: s, byID: map[string]Verdict{}, excused: map[string]bool{}}
	e.res = Result{Policy: displayName(p.Name), OK: true}
	e.res.Target.Transport, e.res.Target.Endpoint = s.Transport, s.Endpoint
	for _, v := range s.Verdicts {
		e.byID[v.ID] = v
	}

	// Exemptions first: every rule below reads their outcome, so which
	// failures are excused has to be settled before anything is counted.
	e.exemptions(now)
	e.target()
	e.mustPass()
	e.mustNotFail()
	e.maxCounts()
	e.minScore()
	e.minCategoryScores()
	e.forbidSeverity()
	return e.res
}

// evaluation is one policy being applied to one subject: the result so far,
// the verdicts by id, and which failures the exemptions excuse.
type evaluation struct {
	p       *Policy
	s       Subject
	res     Result
	byID    map[string]Verdict
	excused map[string]bool
}

// add records one rule's outcome; any unmet rule fails the policy.
func (e *evaluation) add(rule string, met bool, format string, a ...any) {
	e.res.Rules = append(e.res.Rules, RuleResult{Rule: rule, Met: met, Detail: fmt.Sprintf(format, a...)})
	if !met {
		e.res.OK = false
	}
}

// exemptions settles what each exemption does as of now.
func (e *evaluation) exemptions(now time.Time) {
	for _, ex := range e.p.Exemptions {
		id := strings.TrimSpace(ex.Check)
		out := ExemptionResult{
			Check: id, Reason: ex.Reason, Expires: ex.Expires.String(), Ticket: ex.Ticket,
		}
		v, ran := e.byID[id]
		if ran {
			out.Status = v.Status
		}
		failing := ran && (v.Status == string(probe.Fail) || v.Status == string(probe.Warn))
		switch {
		case ex.Expires.expiredOn(now):
			out.Expired = true
			// A failure about the policy, not about the server, and the
			// wording has to say so — the reader's next action is to renew
			// the decision or fix the check, not to argue with passmcp.
			e.add("exemption:"+id, false,
				"the exemption expired on %s and %s", ex.Expires, describeExempted(ran, failing, v))
		case !failing:
			out.Unused = true
		default:
			out.Applied = true
			e.excused[id] = true
		}
		e.res.Exemptions = append(e.res.Exemptions, out)
	}
}

// target checks that the policy is written for this server.
func (e *evaluation) target() {
	t := e.p.Target
	if t == nil {
		return
	}
	met := true
	var why []string
	if t.Transport != "" && t.Transport != e.s.Transport {
		met = false
		why = append(why, fmt.Sprintf("transport is %s, not %s", e.s.Transport, t.Transport))
	}
	if t.Endpoint != "" && t.Endpoint != e.s.Endpoint {
		met = false
		why = append(why, fmt.Sprintf("endpoint is %s, not %s", e.s.Endpoint, t.Endpoint))
	}
	detail := fmt.Sprintf("the policy is written for %s", describeTarget(t))
	if !met {
		detail = "this policy is not written for this server: " + strings.Join(why, "; ")
	}
	e.add("target", met, "%s", detail)
}

// mustPass requires each named check to have run and passed.
func (e *evaluation) mustPass() {
	for _, id := range sortedIDs(e.p.MustPass) {
		v, ran := e.byID[id]
		switch {
		case !ran:
			// The same refusal `passmcp verify --require` makes. A run that did
			// not make the check cannot vouch for it.
			e.add("must_pass:"+id, false, "%s did not run, so nothing says it passed", id)
		case v.Status == string(probe.Pass):
			e.add("must_pass:"+id, true, "%s passed", id)
		default:
			e.add("must_pass:"+id, false, "%s is %s", id, describeVerdict(v))
		}
	}
}

// mustNotFail requires each named check to have run and not failed.
func (e *evaluation) mustNotFail() {
	for _, id := range sortedIDs(e.p.MustNotFail) {
		v, ran := e.byID[id]
		switch {
		case !ran:
			e.add("must_not_fail:"+id, false, "%s did not run, so nothing says it did not fail", id)
		case v.Status == string(probe.Fail):
			e.add("must_not_fail:"+id, false, "%s failed (%s)", id, describeVerdict(v))
		default:
			e.add("must_not_fail:"+id, true, "%s is %s", id, v.Status)
		}
	}
}

// maxCounts applies max_fail and max_warn, not counting excused checks.
func (e *evaluation) maxCounts() {
	if e.p.MaxFail != nil {
		n, ex := countStatus(e.s.Verdicts, probe.Fail, e.excused)
		e.add("max_fail", n <= *e.p.MaxFail, "%s; at most %d allowed%s", plural(n, "check", "failed"), *e.p.MaxFail, excusedNote(ex))
	}
	if e.p.MaxWarn != nil {
		n, ex := countStatus(e.s.Verdicts, probe.Warn, e.excused)
		e.add("max_warn", n <= *e.p.MaxWarn, "%s; at most %d allowed%s", plural(n, "check", "warned"), *e.p.MaxWarn, excusedNote(ex))
	}
}

// minScore applies min_score.
func (e *evaluation) minScore() {
	if e.p.MinScore == nil {
		return
	}
	if e.s.Score == nil {
		// Absent is not zero. A partial run carries no score, and
		// failing a server for that would be a finding about the run.
		e.add("min_score", false, "the run assessed no category, so it carries no score and %g cannot be met", *e.p.MinScore)
		return
	}
	e.add("min_score", e.s.Score.Total >= *e.p.MinScore, "score is %.1f; at least %g required", e.s.Score.Total, *e.p.MinScore)
}

// minCategoryScores applies min_category_score, category by category.
func (e *evaluation) minCategoryScores() {
	for _, cat := range sortedKeys(e.p.MinCategoryScore) {
		want := e.p.MinCategoryScore[cat]
		if e.s.Score == nil {
			e.add("min_category_score:"+cat, false, "the run carries no score, so %s cannot be judged", cat)
			continue
		}
		got, assessed := e.s.Score.Categories[cat]
		if !assessed {
			// Absent is not zero, and it is not "fine" either: a category the
			// run never assessed cannot meet a minimum, and saying it did
			// would be the comfortable mistake.
			e.add("min_category_score:"+cat, false, "%s was not assessed by this run, so %g cannot be met", cat, want)
			continue
		}
		e.add("min_category_score:"+cat, got >= want, "%s scored %.1f; at least %g required", cat, got, want)
	}
}

// forbidSeverity fails the policy on any unexcused failure at or above the
// named severity.
func (e *evaluation) forbidSeverity() {
	if e.p.ForbidSeverity == "" {
		return
	}
	threshold := rank(e.p.ForbidSeverity)
	var over []string
	for _, v := range e.s.Verdicts {
		if v.Status != string(probe.Fail) || e.excused[v.ID] {
			continue
		}
		if rank(v.Severity) >= threshold {
			over = append(over, fmt.Sprintf("%s (%s)", v.ID, v.Severity))
		}
	}
	sort.Strings(over)
	if len(over) == 0 {
		e.add("forbid_severity", true, "no failure at or above %s", e.p.ForbidSeverity)
	} else {
		e.add("forbid_severity", false, "%s at or above %s: %s", plural(len(over), "failure", ""), e.p.ForbidSeverity, strings.Join(over, ", "))
	}
}

// describeExempted says what an expired exemption was covering, because
// "expired" alone does not tell the reader whether it still matters.
func describeExempted(ran, failing bool, v Verdict) string {
	switch {
	case !ran:
		return "the check it names did not run"
	case !failing:
		return fmt.Sprintf("%s now passes, so it can be removed rather than renewed", v.ID)
	default:
		return fmt.Sprintf("%s is still %s", v.ID, describeVerdict(v))
	}
}

// describeVerdict names a status with its severity when it has one.
func describeVerdict(v Verdict) string {
	if v.Severity != "" {
		return fmt.Sprintf("%s (%s)", v.Status, v.Severity)
	}
	return v.Status
}

// describeTarget renders a target the way a policy wrote it.
func describeTarget(t *Target) string {
	switch {
	case t.Transport != "" && t.Endpoint != "":
		return t.Transport + " " + t.Endpoint
	case t.Endpoint != "":
		return t.Endpoint
	default:
		return "any " + t.Transport + " server"
	}
}

// countStatus counts verdicts with a status, leaving out the excused ones and
// reporting how many those were.
func countStatus(vs []Verdict, st probe.Status, excused map[string]bool) (n, ex int) {
	for _, v := range vs {
		if v.Status != string(st) {
			continue
		}
		if excused[v.ID] {
			ex++
			continue
		}
		n++
	}
	return n, ex
}

// excusedNote appends the exempted count, so a passing threshold never hides
// how it was reached.
func excusedNote(ex int) string {
	if ex == 0 {
		return ""
	}
	return fmt.Sprintf(" (%d exempted)", ex)
}

// plural renders "1 check failed" and "3 checks failed".
func plural(n int, noun, verb string) string {
	word := noun
	if n != 1 {
		word += "s"
	}
	out := fmt.Sprintf("%d %s", n, word)
	if verb != "" {
		out += " " + verb
	}
	return out
}

func sortedIDs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]float64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
