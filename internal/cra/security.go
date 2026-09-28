// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package cra checks the evidence passmcp publishes for the EU Cyber
// Resilience Act (Regulation (EU) 2024/2847): the security policy, the
// release assets, the compliance page's claims, and the VEX statement a
// release carries for vulnerabilities in dependencies that do not affect
// it.
//
// Each check returns the problems it found, never a bare boolean, so the
// release preflight can print what is missing instead of "check failed".
// Nothing here makes a network request; callers supply the text, the asset
// list or the govulncheck output.
package cra

import (
	"regexp"
	"strings"
)

// securityRequirements are what SECURITY.md must state. Each is matched
// case-insensitively against the whole policy, and the message names what
// is missing in the reader's terms, not the pattern's.
var securityRequirements = []struct {
	pattern *regexp.Regexp
	missing string
}{
	{regexp.MustCompile(`(?i)security/advisories/new|mailto:[^\s)]+@`), "a private report channel (GitHub private vulnerability reporting or an e-mail address)"},
	{regexp.MustCompile(`(?i)acknowledg\w*[^.]*\b72\s*hours`), "the acknowledgement time (72 hours)"},
	{regexp.MustCompile(`(?i)actively exploited`), "the scope of the CRA timeline (actively exploited vulnerabilities)"},
	{regexp.MustCompile(`(?i)early warning[^.]*\b24\s*hours`), "the CRA early warning (within 24 hours)"},
	{regexp.MustCompile(`(?i)notification[^.]*\b72\s*hours`), "the CRA vulnerability notification (within 72 hours)"},
	{regexp.MustCompile(`(?i)final report[^.]*\b14\s*days`), "the CRA final report (within 14 days)"},
}

// CheckSecurityPolicy returns what the security policy text fails to state.
// An empty result means the policy names the report channel, the
// acknowledgement time and the CRA reporting timeline for actively
// exploited vulnerabilities.
func CheckSecurityPolicy(policy string) []string {
	text := normalise(policy)
	var problems []string
	for _, r := range securityRequirements {
		if !r.pattern.MatchString(text) {
			problems = append(problems, "SECURITY.md does not state "+r.missing)
		}
	}
	return problems
}

// normalise folds line breaks so a requirement that wraps across lines in
// the Markdown source still matches.
func normalise(text string) string {
	return strings.Join(strings.Fields(text), " ")
}
