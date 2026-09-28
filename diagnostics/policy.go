// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package diagnostics exercises a connected MCP server the way an agent
// would and produces an observability report with a quality score.
//
// It follows a do-no-harm rule: by default only tools that declare
// readOnlyHint are invoked. Tools without annotations are, per the MCP
// specification defaults, destructive and are skipped unless the caller
// opts in with Policy.AllowMutations.
package diagnostics

import (
	"slices"

	"satellion.com/passmcp"
)

// Policy decides which tools the harness may invoke.
type Policy struct {
	// AllowMutations permits non-read-only tools. Destructive tools still
	// require AllowDestructive.
	AllowMutations bool
	// AllowDestructive permits tools whose destructiveHint is true or
	// unset. Implies AllowMutations.
	AllowDestructive bool
	// Deny lists tool names never to invoke regardless of hints.
	Deny []string
	// Only, when non-empty, restricts execution to these tool names (the
	// hint checks still apply).
	Only []string
}

// Decision is the outcome of Policy.Decide.
type Decision struct {
	Execute bool
	Reason  string
}

// Decide applies the policy to one tool.
func (p Policy) Decide(t passmcp.Tool) Decision {
	if slices.Contains(p.Deny, t.Name) {
		return Decision{false, "denied by policy"}
	}
	if len(p.Only) > 0 && !slices.Contains(p.Only, t.Name) {
		return Decision{false, "not in policy allow-list"}
	}
	if t.IsReadOnly() {
		return Decision{true, "readOnlyHint"}
	}
	if t.IsDestructive() {
		if p.AllowDestructive {
			return Decision{true, "destructive, AllowDestructive set"}
		}
		if t.Annotations == nil || t.Annotations.DestructiveHint == nil {
			return Decision{false, "no annotations: destructive by spec default"}
		}
		return Decision{false, "destructiveHint"}
	}
	if p.AllowMutations || p.AllowDestructive {
		return Decision{true, "mutating, AllowMutations set"}
	}
	return Decision{false, "mutating tool; set AllowMutations"}
}
