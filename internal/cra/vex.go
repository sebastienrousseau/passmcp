// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cra

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
)

// OpenVEXContext is the OpenVEX specification version the documents use.
const OpenVEXContext = "https://openvex.dev/ns/v0.2.0"

// VEX statuses and justifications, as OpenVEX defines them.
const (
	StatusNotAffected = "not_affected"
	StatusAffected    = "affected"

	// JustificationNotPresent: the vulnerable package is not imported at
	// all, only its module is required.
	JustificationNotPresent = "vulnerable_code_not_present"
	// JustificationNotInPath: the package is imported, but no vulnerable
	// symbol is reachable from passmcp's code.
	JustificationNotInPath = "vulnerable_code_not_in_execute_path"
)

// VEX is an OpenVEX document.
type VEX struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id"`
	Author     string      `json:"author"`
	Timestamp  string      `json:"timestamp"`
	Version    int         `json:"version"`
	Statements []Statement `json:"statements"`
}

// Statement is one OpenVEX statement: a vulnerability's status for the
// product.
type Statement struct {
	Vulnerability   Vulnerability `json:"vulnerability"`
	Products        []Product     `json:"products"`
	Status          string        `json:"status"`
	Justification   string        `json:"justification,omitempty"`
	ImpactStatement string        `json:"impact_statement,omitempty"`
	ActionStatement string        `json:"action_statement,omitempty"`
}

// Vulnerability names a vulnerability and its aliases (CVE, GHSA).
type Vulnerability struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
}

// Product is the product a statement is about, with the vulnerable
// dependency as a subcomponent.
type Product struct {
	ID            string      `json:"@id"`
	Subcomponents []Component `json:"subcomponents,omitempty"`
}

// Component is a subcomponent, identified by package URL.
type Component struct {
	ID string `json:"@id"`
}

// govulncheck's JSON stream, as much of it as a VEX statement needs.
type govulnMessage struct {
	OSV     *govulnOSV     `json:"osv"`
	Finding *govulnFinding `json:"finding"`
}

type govulnOSV struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
}

type govulnFinding struct {
	OSV          string        `json:"osv"`
	FixedVersion string        `json:"fixed_version"`
	Trace        []govulnFrame `json:"trace"`
}

type govulnFrame struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Package  string `json:"package"`
	Function string `json:"function"`
}

// reach is how far a vulnerability reaches into passmcp: govulncheck reports
// a finding at the module, package or symbol level, and the deepest one
// decides the statement.
type reach int

const (
	reachModule reach = iota
	reachPackage
	reachSymbol
)

type vulnState struct {
	aliases []string
	reach   reach
	module  string
	version string
	fixed   string
}

// readGovulncheck reads a `govulncheck -format json` stream into one state
// per vulnerability.
func readGovulncheck(r io.Reader) (map[string]*vulnState, error) {
	dec := json.NewDecoder(r)
	aliases := map[string][]string{}
	vulns := map[string]*vulnState{}
	for {
		var m govulnMessage
		if err := dec.Decode(&m); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("reading govulncheck output: %w", err)
		}
		if m.OSV != nil {
			aliases[m.OSV.ID] = m.OSV.Aliases
		}
		if f := m.Finding; f != nil && len(f.Trace) > 0 {
			recordFinding(vulns, f)
		}
	}
	for id, v := range vulns {
		v.aliases = aliases[id]
	}
	return vulns, nil
}

// recordFinding folds one finding into its vulnerability's state, keeping
// the deepest reach seen.
func recordFinding(vulns map[string]*vulnState, f *govulnFinding) {
	top := f.Trace[0]
	r := reachModule
	switch {
	case top.Function != "":
		r = reachSymbol
	case top.Package != "":
		r = reachPackage
	}
	v, ok := vulns[f.OSV]
	if !ok {
		v = &vulnState{module: top.Module, version: top.Version, fixed: f.FixedVersion}
		vulns[f.OSV] = v
	}
	if r > v.reach {
		v.reach = r
	}
}

// BuildVEX turns govulncheck's output into an OpenVEX document for product
// (a package URL such as pkg:golang/satellion.com/passmcp@v0.0.1).
// A vulnerability whose code passmcp calls is `affected`; one whose package
// is imported but whose vulnerable symbols are unreachable, or whose
// package is not imported at all, is `not_affected` with the justification
// that says which. Statements are sorted by vulnerability ID so the same
// input always gives the same document.
func BuildVEX(r io.Reader, product, author string, at time.Time) (VEX, error) {
	vulns, err := readGovulncheck(r)
	if err != nil {
		return VEX{}, err
	}
	ids := make([]string, 0, len(vulns))
	for id := range vulns {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	doc := VEX{
		Context:   OpenVEXContext,
		ID:        product + "#vex",
		Author:    author,
		Timestamp: at.UTC().Format(time.RFC3339),
		Version:   1,
	}
	for _, id := range ids {
		doc.Statements = append(doc.Statements, statementFor(id, vulns[id], product))
	}
	return doc, nil
}

// statementFor writes one vulnerability's statement.
func statementFor(id string, v *vulnState, product string) Statement {
	s := Statement{
		Vulnerability: Vulnerability{Name: id, Aliases: v.aliases},
		Products: []Product{{
			ID:            product,
			Subcomponents: []Component{{ID: "pkg:golang/" + v.module + "@" + v.version}},
		}},
	}
	switch v.reach {
	case reachSymbol:
		s.Status = StatusAffected
		s.ActionStatement = "Upgrade " + v.module + " to " + fixedOr(v.fixed) + " and release; see SECURITY.md."
	case reachPackage:
		s.Status = StatusNotAffected
		s.Justification = JustificationNotInPath
		s.ImpactStatement = "govulncheck found no call path from passmcp to the vulnerable symbols."
	default:
		s.Status = StatusNotAffected
		s.Justification = JustificationNotPresent
		s.ImpactStatement = "passmcp requires the module but does not import the vulnerable package."
	}
	return s
}

// fixedOr names the fixed version, or says there is none yet.
func fixedOr(v string) string {
	if v == "" {
		return "a fixed version once one exists"
	}
	return v
}

// NotAffected counts the statements that say a vulnerability does not
// affect the product: the ones a release attaches a VEX document for.
func (d VEX) NotAffected() int {
	n := 0
	for _, s := range d.Statements {
		if s.Status == StatusNotAffected {
			n++
		}
	}
	return n
}

var validStatus = map[string]bool{
	StatusNotAffected: true, StatusAffected: true, "fixed": true, "under_investigation": true,
}

// ValidateVEX returns every way a document departs from the OpenVEX rules
// passmcp relies on: the context, an author and a parsable timestamp, and in
// each statement a vulnerability name, at least one product, a known
// status, a justification or impact statement for `not_affected`, and an
// action statement for `affected`.
func ValidateVEX(d VEX) []string {
	var problems []string
	if d.Context != OpenVEXContext {
		problems = append(problems, fmt.Sprintf("@context is %q, want %q", d.Context, OpenVEXContext))
	}
	if d.ID == "" || d.Author == "" {
		problems = append(problems, "@id and author are required")
	}
	if _, err := time.Parse(time.RFC3339, d.Timestamp); err != nil {
		problems = append(problems, "timestamp is not RFC 3339: "+d.Timestamp)
	}
	for i, s := range d.Statements {
		problems = append(problems, statementProblems(i, s)...)
	}
	return problems
}

// statementProblems validates one statement.
func statementProblems(i int, s Statement) []string {
	var problems []string
	at := fmt.Sprintf("statement %d (%s)", i, s.Vulnerability.Name)
	if s.Vulnerability.Name == "" {
		problems = append(problems, at+": no vulnerability name")
	}
	if len(s.Products) == 0 {
		problems = append(problems, at+": no product")
	}
	if !validStatus[s.Status] {
		problems = append(problems, at+": unknown status "+s.Status)
	}
	if s.Status == StatusNotAffected && s.Justification == "" && s.ImpactStatement == "" {
		problems = append(problems, at+": not_affected needs a justification or impact statement")
	}
	if s.Status == StatusAffected && s.ActionStatement == "" {
		problems = append(problems, at+": affected needs an action statement")
	}
	return problems
}
