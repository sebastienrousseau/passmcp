// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package policy is a reviewable statement of what a team will accept from an
// MCP server.
//
// passmcp could already gate a run: a failing finding exits 2, and `passmcp
// verify` takes --require, --max-fail and --min-score. That is enough for one
// pipeline and not enough for an organisation, for three reasons a flag
// cannot fix.
//
// A flag is not reviewable. "Why does this server pass?" is answered by
// reading a CI YAML file, and a change to what the company accepts arrives as
// a diff to a shell line nobody reviews. A policy is a file with a name and a
// version that goes through the same review as code.
//
// A flag cannot carry an exception. Real gates are adopted only if a team can
// say "this one check, on this server, for this reason, until this date" —
// otherwise the gate is turned off wholesale on its first inconvenient
// morning. So an exemption is a first-class object here, and it is invalid
// without a reason and an expiry: an exemption with no expiry is a permanent
// hole nobody ever revisits, which is the state most security exceptions end
// up in.
//
// A flag cannot be refused. A policy file written for a later version of
// passmcp, or carrying a rule this build does not implement, is rejected rather
// than partly applied — because a policy engine that ignores what it does not
// understand is a policy engine that approves things. That is the one property
// worth being inflexible about.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Version is the policy format this build implements.
const Version = 1

// Severity ranks a failure. The order is the comparison: Critical is the
// worst, and forbidding Major forbids Critical too.
type Severity string

// The severities a policy can name, worst first.
const (
	Critical Severity = "critical"
	Major    Severity = "major"
	Minor    Severity = "minor"
)

// rank orders severities so "at or above" means something. A severity the
// policy does not name ranks below everything, so it never trips a threshold
// by accident.
func rank(s Severity) int {
	switch s {
	case Critical:
		return 3
	case Major:
		return 2
	case Minor:
		return 1
	}
	return 0
}

// Policy is what a team will accept.
//
// Every numeric rule is a pointer because "not stated" and "zero" are
// different policies, and zero is the strictest useful value of most of them.
// The same reasoning as the --max-fail flag, where a sentinel would have had
// to sit one below the strictest setting.
type Policy struct {
	// Version is the policy format. A file from a later version is refused.
	Version int `json:"version"`
	// Name is what the report calls this policy, so a failure says which
	// document said no.
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`

	// Target constrains which server the policy may be applied to. Optional:
	// most policies are written for a fleet, not an address.
	Target *Target `json:"target,omitempty"`

	// MustPass names checks whose verdict has to be a pass. A check that did
	// not run does not pass: a run that never made the check cannot vouch
	// for it, and reading absence as success is how a gate becomes
	// decoration.
	MustPass []string `json:"must_pass,omitempty"`
	// MustNotFail is the weaker form, for a check where a warning is
	// tolerable and a failure is not.
	MustNotFail []string `json:"must_not_fail,omitempty"`

	MaxFail *int `json:"max_fail,omitempty"`
	MaxWarn *int `json:"max_warn,omitempty"`

	MinScore *float64 `json:"min_score,omitempty"`
	// MinCategoryScore gates a single area, which is how a team says
	// "authorization matters more here than the total does". A category the
	// run did not assess cannot meet a minimum, and says so.
	MinCategoryScore map[string]float64 `json:"min_category_score,omitempty"`

	// ForbidSeverity refuses any failure at or above this severity, whatever
	// the counts say.
	ForbidSeverity Severity `json:"forbid_severity,omitempty"`

	// Exemptions are the decisions that make a gate adoptable. Each names one
	// check, why it is excused, and when the excuse runs out.
	Exemptions []Exemption `json:"exemptions,omitempty"`
}

// Target is the server a policy is written for.
type Target struct {
	// Transport is "http" or "stdio". Empty matches either.
	Transport string `json:"transport,omitempty"`
	// Endpoint is the exact URL or command line. Empty matches any.
	Endpoint string `json:"endpoint,omitempty"`
}

// Exemption excuses one check on purpose.
type Exemption struct {
	Check string `json:"check"`
	// Reason is required. An exemption whose reason is "temporary" is the
	// one still in the file three years later, so the field exists to make
	// somebody write a sentence a reviewer can disagree with.
	Reason string `json:"reason"`
	// Expires is required, as a date. The whole difference between an
	// exception and a hole is that an exception has a date on it.
	Expires Date `json:"expires"`
	// Ticket is optional and is where a reader goes to find the decision.
	Ticket string `json:"ticket,omitempty"`
}

// Date is a calendar day, written YYYY-MM-DD.
//
// Not a time.Time: an expiry with a clock time in it invites a policy that
// passes in one timezone and fails in another, and nobody writing "this
// exception runs out at the end of March" means 00:00:00Z.
type Date struct{ time.Time }

const dateLayout = "2006-01-02"

// MarshalJSON writes the date back in the form it was read.
func (d Date) MarshalJSON() ([]byte, error) {
	if d.IsZero() {
		return []byte(`""`), nil
	}
	return json.Marshal(d.Format(dateLayout))
}

// UnmarshalJSON reads YYYY-MM-DD and nothing else.
func (d *Date) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("a date must be a string like 2027-03-31: %w", err)
	}
	if strings.TrimSpace(s) == "" {
		d.Time = time.Time{}
		return nil
	}
	t, err := time.Parse(dateLayout, s)
	if err != nil {
		return fmt.Errorf("%q is not a date in YYYY-MM-DD form", s)
	}
	d.Time = t
	return nil
}

// String renders the date, or "never" for the zero value.
func (d Date) String() string {
	if d.IsZero() {
		return "never"
	}
	return d.Format(dateLayout)
}

// expiredOn reports whether the exemption has run out by the given day. The
// expiry day itself is still covered — "expires 2027-03-31" reads as "good
// through the 31st", which is what everybody means by it.
func (d Date) expiredOn(now time.Time) bool {
	if d.IsZero() {
		return true
	}
	return now.UTC().Truncate(24 * time.Hour).After(d.Time)
}

// Load reads a policy file.
//
// Strict about unknown fields, and that is the point: a misspelled
// "must_pas" would otherwise be a rule that silently does not apply, which is
// the worst failure mode a gate has — it reports success.
func Load(path string) (*Policy, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the caller named the file
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse reads a policy from bytes.
func Parse(b []byte) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate reports every way a policy cannot be applied as written.
func (p *Policy) Validate() error {
	var problems []string
	note := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }

	p.validateHeader(note)
	p.validateLimits(note)
	seenEx := p.validateExemptions(note)
	p.validateCheckLists(seenEx, note)

	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("policy %s:\n  - %s", displayName(p.Name), strings.Join(problems, "\n  - "))
}

// noter records one problem with a policy.
type noter func(format string, a ...any)

// validateHeader checks the version, the name and the target block.
func (p *Policy) validateHeader(note noter) {
	switch {
	case p.Version == 0:
		note("no version: a policy with no version cannot be read safely by a later passmcp")
	case p.Version > Version:
		// Refused, not downgraded. A rule this build does not implement
		// would otherwise be a rule that does not apply, and the run would
		// report a pass it did not earn.
		note("version %d, and this passmcp implements %d: upgrade passmcp rather than applying a policy it cannot fully enforce",
			p.Version, Version)
	case p.Version < 0:
		note("version %d is not a version", p.Version)
	}
	if strings.TrimSpace(p.Name) == "" {
		note("no name: a failure has to be able to say which policy said no")
	}
	if p.Target != nil {
		switch p.Target.Transport {
		case "", "http", "stdio":
		default:
			note("target transport %q is neither http nor stdio", p.Target.Transport)
		}
		if p.Target.Transport == "" && strings.TrimSpace(p.Target.Endpoint) == "" {
			note("the target block constrains nothing; remove it or fill it in")
		}
	}
}

// validateLimits checks the severity threshold, the counts and the scores.
func (p *Policy) validateLimits(note noter) {
	if p.ForbidSeverity != "" && rank(p.ForbidSeverity) == 0 {
		note("forbid_severity %q is not critical, major or minor", p.ForbidSeverity)
	}
	for _, n := range []struct {
		field string
		v     *int
	}{{"max_fail", p.MaxFail}, {"max_warn", p.MaxWarn}} {
		if n.v != nil && *n.v < 0 {
			note("%s is %d; a negative allowance cannot be met by any run", n.field, *n.v)
		}
	}
	if p.MinScore != nil && (*p.MinScore < 0 || *p.MinScore > 100) {
		note("min_score is %g, and a score is 0 to 100", *p.MinScore)
	}
	for cat, v := range p.MinCategoryScore {
		if strings.TrimSpace(cat) == "" {
			note("a min_category_score entry has no category name")
		}
		if v < 0 || v > 100 {
			note("min_category_score for %s is %g, and a score is 0 to 100", cat, v)
		}
	}
}

// validateExemptions checks each exemption and returns the checks exempted.
func (p *Policy) validateExemptions(note noter) map[string]bool {
	seenEx := map[string]bool{}
	for _, e := range p.Exemptions {
		id := strings.TrimSpace(e.Check)
		switch {
		case id == "":
			note("an exemption names no check")
			continue
		case seenEx[id]:
			note("%s is exempted twice, so which reason applies is undecided", id)
		}
		seenEx[id] = true
		if strings.TrimSpace(e.Reason) == "" {
			note("the exemption for %s has no reason, which makes it an undocumented hole rather than a decision", id)
		}
		if e.Expires.IsZero() {
			note("the exemption for %s has no expiry: an exception with no date on it is a permanent hole", id)
		}
	}
	return seenEx
}

// validateCheckLists checks must_pass and must_not_fail against themselves
// and against the exemptions.
func (p *Policy) validateCheckLists(seenEx map[string]bool, note noter) {
	// A check that is both required and exempted has two answers. Refusing is
	// better than picking one, because whichever passmcp picked would surprise
	// half of its readers.
	for _, id := range append(append([]string{}, p.MustPass...), p.MustNotFail...) {
		if seenEx[strings.TrimSpace(id)] {
			note("%s is both required and exempted; remove one", strings.TrimSpace(id))
		}
	}
	for _, list := range []struct {
		field string
		ids   []string
	}{{"must_pass", p.MustPass}, {"must_not_fail", p.MustNotFail}} {
		seen := map[string]bool{}
		for _, id := range list.ids {
			id = strings.TrimSpace(id)
			if id == "" {
				note("%s has an empty check id", list.field)
				continue
			}
			if seen[id] {
				note("%s names %s twice", list.field, id)
			}
			seen[id] = true
		}
	}
}

// displayName is what an error calls a policy that may not have a name yet.
func displayName(name string) string {
	if strings.TrimSpace(name) == "" {
		return "(unnamed)"
	}
	return name
}

// Rules reports whether the policy states any rule at all.
//
// A policy that only describes itself is almost certainly a mistake — a file
// somebody started and did not finish — and it would otherwise pass every
// subject silently. The caller decides what to do about it; Validate does not
// refuse it, because an empty policy is a legitimate starting point for a
// team that wants the reporting before the gating.
func (p *Policy) Rules() int {
	n := len(p.MustPass) + len(p.MustNotFail) + len(p.MinCategoryScore)
	for _, set := range []bool{p.MaxFail != nil, p.MaxWarn != nil, p.MinScore != nil, p.ForbidSeverity != "", p.Target != nil} {
		if set {
			n++
		}
	}
	return n
}
