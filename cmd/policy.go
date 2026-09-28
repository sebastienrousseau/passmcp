// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"fmt"
	"io"

	"satellion.com/passmcp/internal/policy"
)

// writePolicyResult renders a policy's answer.
//
// Rules first, then exemptions, then the verdict. Exemptions are printed even
// when every rule held, because an exemption that is about to expire and one
// nobody needs any more are both things a reviewer has to see — and the only
// moment anybody looks at a policy file is when they are reading its output.
func writePolicyResult(w io.Writer, r policy.Result) {
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }

	p("\npolicy     %s\n", r.Policy)
	if len(r.Rules) == 0 && len(r.Exemptions) == 0 {
		p("\nthe policy states no rule, so nothing was judged.\n")
		return
	}
	for _, rule := range r.Rules {
		p("%s %-32s %s\n", mark(rule.Met), rule.Rule, rule.Detail)
	}
	for _, e := range r.Exemptions {
		switch {
		case e.Expired:
			// Already counted as a failed rule; this line is the detail a
			// reader needs to act, which is who decided it and where.
			p("%s %-32s expired %s — %s\n", mark(false), "exemption:"+e.Check, e.Expires, withTicket(e))
		case e.Unused:
			p("%s %-32s %s no longer needs it (%s); it can be removed\n",
				"·", "exemption:"+e.Check, e.Check, statusOrAbsent(e))
		default:
			p("%s %-32s %s excused until %s — %s\n",
				"·", "exemption:"+e.Check, e.Status, e.Expires, withTicket(e))
		}
	}
	if r.OK {
		p("\nthe policy is met.\n")
		return
	}
	p("\nthe policy is not met.\n")
}

// mark is the per-rule glyph. A dot rather than a tick for an exemption: it
// is neither a pass nor a failure, it is a decision somebody made.
func mark(met bool) string {
	if met {
		return "✓"
	}
	return "✕"
}

// withTicket appends where the decision is recorded, when the policy says.
func withTicket(e policy.ExemptionResult) string {
	if e.Ticket == "" {
		return e.Reason
	}
	return e.Reason + " (" + e.Ticket + ")"
}

// statusOrAbsent describes a check an exemption names that is no longer
// failing, distinguishing "it passes now" from "it did not run".
func statusOrAbsent(e policy.ExemptionResult) string {
	if e.Status == "" {
		return "did not run"
	}
	return e.Status
}
