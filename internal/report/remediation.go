// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

import "strings"

// A finding tells somebody what is wrong. It does not tell them what to do,
// and the gap between those two is where a report stops being useful.
//
// "add outputSchema and return structuredContent" is correct and it assumes
// the reader already knows what changed, why it changed, and where in their
// code it lives. The person reading this report is often not the person who
// wrote the server, and is frequently reading it to decide whether to adopt
// the thing at all.
//
// So each entry here answers two questions in order: what does this mean,
// and what do I change. The steps are imperative and name the actual field,
// header or method — a step a reader cannot act on without a search engine
// is a step that has not been written yet.
//
// This is documentation, not observation. It is keyed by check id and
// attached at render time rather than carried on every Finding, because it
// is identical for every run and would otherwise be duplicated into every
// JSON report. remediation_test.go fails when a key here is not a real
// check id.

// Step is one imperative action, with the reason it is the action.
// The json tags matter: this type reaches a consumer through the report's
// `guidance` dictionary under --guidance, and every other field in that
// document is lower_snake. Exported Go names would have made this the one
// object in the report that is spelled differently.
type Step struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// Remediation is the guidance for one check.
type Remediation struct {
	// Means explains the finding in terms of the protocol, for a reader who
	// did not follow the specification change that produced it.
	Means string `json:"means"`
	// Steps are what to change, in the order they are worth doing.
	Steps []Step `json:"steps"`
	// Note is the shortcut, where one exists — usually that an SDK upgrade
	// does most of this. Saying so is not undermining the advice; it is the
	// difference between a report somebody acts on and one they postpone.
	Note string `json:"note,omitempty"`
}

// remediations is keyed by check id. Families are keyed by their literal
// prefix with the trailing dot, matching probe.DocFamilies.
var remediations = mergeRemediations(remediationGroups)

// remediationGroups are the per-area tables remediations is built from, one
// per file. remediation_test.go checks no check id appears in two of them,
// which a single map literal would have caught at compile time.
var remediationGroups = []map[string]Remediation{
	connectRemediations,
	stdioRemediations,
	handshakeRemediations,
	protocolRemediations,
	catalogRemediations,
	catalogTextRemediations,
	executionRemediations,
	resilienceRemediations,
	attackRemediations,
	a2aRemediations,
}

// mergeRemediations flattens the per-area tables into one.
func mergeRemediations(groups []map[string]Remediation) map[string]Remediation {
	out := make(map[string]Remediation)
	for _, g := range groups {
		for id, r := range g {
			out[id] = r
		}
	}
	return out
}

// RemediationFor returns the guidance for a check id.
//
// A family instance resolves to its family, the same way probe.DocURL does,
// because the guidance is about the family and the instance is whatever this
// particular server happened to have.
func RemediationFor(id string) (Remediation, bool) {
	if r, ok := remediations[id]; ok {
		return r, true
	}
	for key := range remediations {
		if strings.HasSuffix(key, ".") && strings.HasPrefix(id, key) {
			return remediations[key], true
		}
	}
	return Remediation{}, false
}
