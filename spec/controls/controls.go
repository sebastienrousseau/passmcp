// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Package controls maps passmcp's checks to the controls of compliance
// frameworks — SOC 2 Trust Services Criteria, ISO/IEC 27001:2022 Annex A
// and GDPR articles — and assesses a set of verdicts against them.
//
// The mapping is data, not code. Each framework is one JSON file in this
// directory, published under Apache-2.0 with the rest of the format (ADR
// 0011), so a GRC tool can read it without taking on the engine's licence.
// Every check in passmcp's inventory has an entry in every file: either the
// control identifiers it evidences, or "none" with the reason it evidences
// none. A criterion no check can evidence is listed with the reason too, so
// an evidence bundle can say "not covered by passmcp" instead of leaving a
// gap an auditor would read as an oversight.
//
// Nothing here makes an organisation compliant. A CPA firm attests SOC 2,
// an accredited body certifies ISO 27001, and GDPR is the controller's
// obligation. passmcp supplies dated, reproducible evidence for the controls
// its checks touch, and says plainly which ones they do not.
package controls

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

//go:embed soc2.json iso27001.json gdpr.json iso27001-2022-annex-a.json
var files embed.FS

// Framework names one mapping file.
type Framework string

// The frameworks passmcp maps its checks to.
const (
	SOC2     Framework = "soc2"
	ISO27001 Framework = "iso27001"
	GDPR     Framework = "gdpr"
)

// Frameworks lists every framework in a stable order.
var Frameworks = []Framework{SOC2, ISO27001, GDPR}

// ParseFramework accepts a framework name as a flag gives it.
func ParseFramework(s string) (Framework, error) {
	f := Framework(strings.ToLower(strings.TrimSpace(s)))
	for _, known := range Frameworks {
		if f == known {
			return f, nil
		}
	}
	return "", fmt.Errorf("unknown framework %q: use one of soc2, iso27001, gdpr", s)
}

// Criterion is one control, criterion or article of a framework.
type Criterion struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// Reason is why no passmcp check evidences this criterion. It is set
	// exactly when no check maps to it.
	Reason string `json:"reason,omitempty"`
}

// Entry is one check's mapping: the controls it evidences, or none and why.
type Entry struct {
	Controls []string `json:"controls,omitempty"`
	None     string   `json:"none,omitempty"`
}

// Mapping is one framework's file.
type Mapping struct {
	Framework Framework        `json:"framework"`
	Name      string           `json:"name"`
	Version   string           `json:"version"`
	Note      string           `json:"note"`
	Criteria  []Criterion      `json:"criteria"`
	Checks    map[string]Entry `json:"checks"`
}

var (
	loadOnce sync.Once
	loaded   map[Framework]*Mapping
	loadErr  error
)

// Load returns a framework's mapping, parsed once from the embedded file.
func Load(f Framework) (*Mapping, error) {
	loadOnce.Do(loadAll)
	if loadErr != nil {
		return nil, loadErr
	}
	m, ok := loaded[f]
	if !ok {
		return nil, fmt.Errorf("unknown framework %q", f)
	}
	return m, nil
}

func loadAll() {
	loaded = map[Framework]*Mapping{}
	for _, f := range Frameworks {
		b, err := files.ReadFile(string(f) + ".json")
		if err != nil {
			loadErr = err
			return
		}
		var m Mapping
		if err := json.Unmarshal(b, &m); err != nil {
			loadErr = fmt.Errorf("%s.json: %w", f, err)
			return
		}
		loaded[f] = &m
	}
}

// Lookup returns the entry for a check id. A computed family id —
// auth.source.<field> — resolves to its family's entry, "auth.source.*",
// as it does in the published inventory.
func (m *Mapping) Lookup(id string) (Entry, bool) {
	if e, ok := m.Checks[id]; ok {
		return e, true
	}
	for key, e := range m.Checks {
		if prefix, ok := strings.CutSuffix(key, "*"); ok && strings.HasPrefix(id, prefix) {
			return e, true
		}
	}
	return Entry{}, false
}

// Set is the controls one finding evidences, in every framework.
//
// Every framework is a list, empty when the check evidences no control
// there, so a consumer never has to tell a missing field from an empty
// one. For always returns non-nil lists, which is what makes them marshal
// as [] rather than null; a custom marshaller would have done the same at
// the cost of an allocation per finding in every JSON report.
type Set struct {
	SOC2     []string `json:"soc2"`
	ISO27001 []string `json:"iso27001"`
	GDPR     []string `json:"gdpr"`
}

// For returns the controls a check evidences in every framework. An id no
// mapping knows gets empty lists, never an error: a report must still be
// written for a check the mapping has not caught up with, and the CI gate
// is what stops that shipping.
func For(id string) Set {
	var s Set
	for _, f := range Frameworks {
		m, err := Load(f)
		if err != nil {
			return Set{SOC2: []string{}, ISO27001: []string{}, GDPR: []string{}}
		}
		e, _ := m.Lookup(id)
		ids := append([]string{}, e.Controls...)
		switch f {
		case SOC2:
			s.SOC2 = ids
		case ISO27001:
			s.ISO27001 = ids
		case GDPR:
			s.GDPR = ids
		}
	}
	return s
}

// Problems lists every way the mapping disagrees with an inventory of
// check ids: a check with no entry, an entry for no check, an entry with
// neither controls nor a reason, a control the framework does not define,
// and a criterion that is unmapped without a reason, or mapped and still
// carrying one. An empty result is the CI gate passing.
func (m *Mapping) Problems(inventory []string) []string {
	var out []string
	known := map[string]bool{}
	for _, c := range m.Criteria {
		known[c.ID] = true
	}
	inInventory := map[string]bool{}
	for _, id := range inventory {
		inInventory[id] = true
		if _, ok := m.Checks[id]; !ok {
			out = append(out, fmt.Sprintf("%s: check %s has no entry", m.Framework, id))
		}
	}
	used := map[string]bool{}
	for id, e := range m.Checks {
		if !inInventory[id] {
			out = append(out, fmt.Sprintf("%s: entry %s names no check in the inventory", m.Framework, id))
		}
		out = append(out, entryProblems(m.Framework, id, e, known, used)...)
	}
	for _, c := range m.Criteria {
		switch {
		case !used[c.ID] && strings.TrimSpace(c.Reason) == "":
			out = append(out, fmt.Sprintf("%s: %s is evidenced by no check and gives no reason", m.Framework, c.ID))
		case used[c.ID] && c.Reason != "":
			out = append(out, fmt.Sprintf("%s: %s is evidenced by a check but still says why it is not", m.Framework, c.ID))
		}
	}
	sort.Strings(out)
	return out
}

func entryProblems(f Framework, id string, e Entry, known, used map[string]bool) []string {
	var out []string
	switch {
	case len(e.Controls) == 0 && strings.TrimSpace(e.None) == "":
		out = append(out, fmt.Sprintf("%s: %s maps to nothing and gives no reason", f, id))
	case len(e.Controls) > 0 && e.None != "":
		out = append(out, fmt.Sprintf("%s: %s maps to controls and also says none", f, id))
	}
	for _, c := range e.Controls {
		used[c] = true
		if !known[c] {
			out = append(out, fmt.Sprintf("%s: %s maps to %s, which the framework does not define", f, id, c))
		}
	}
	return out
}

// AnnexA returns the 93 control identifiers of ISO/IEC 27001:2022 Annex A.
func AnnexA() ([]Criterion, error) {
	b, err := files.ReadFile("iso27001-2022-annex-a.json")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Controls []Criterion `json:"controls"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	return doc.Controls, nil
}
