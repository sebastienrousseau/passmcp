// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cra

import "regexp"

var (
	// advisoryID matches the identifiers a fixed vulnerability is published
	// under: a GitHub advisory, a CVE, or a Go vulnerability database entry.
	advisoryID = regexp.MustCompile(`\b(?:GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|CVE-\d{4}-\d{4,}|GO-\d{4}-\d{4,})\b`)
	// affectedVersions matches the affected-range statement, e.g.
	// "Affected versions: v0.0.3 to v0.0.8".
	affectedVersions = regexp.MustCompile(`(?i)affected versions:\s*\S`)
	// securityFixLabel is how a highlight announces a fixed vulnerability.
	securityFixLabel = regexp.MustCompile(`^[-*]\s+\*\*Security fix\b`)
)

// CheckAdvisoryNotes returns the release-notes highlights that announce a
// fixed vulnerability without saying which, or for which versions. The
// convention, set out in docs/releases/README.md: a highlight whose label
// begins "Security fix" names its advisory ID (GHSA, CVE or GO) and
// carries "Affected versions:", and any highlight that cites an advisory
// ID carries the affected versions too.
func CheckAdvisoryNotes(md string) []string {
	var problems []string
	for _, c := range claims(md) {
		hasID := advisoryID.MatchString(c)
		if securityFixLabel.MatchString(c) && !hasID {
			problems = append(problems, "a security fix names no advisory ID: "+truncateClaim(c))
		}
		if (hasID || securityFixLabel.MatchString(c)) && !affectedVersions.MatchString(c) {
			problems = append(problems, "an advisory states no affected versions: "+truncateClaim(c))
		}
	}
	return problems
}

// AdvisoryIDs lists the advisory identifiers a text cites, in order and
// without repeats: what a release's notes say it fixed.
func AdvisoryIDs(text string) []string {
	seen := map[string]bool{}
	var ids []string
	for _, id := range advisoryID.FindAllString(text, -1) {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids
}
