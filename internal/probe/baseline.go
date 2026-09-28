// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"fmt"
	"strings"

	"satellion.com/passmcp/internal/baseline"
)

// Every other check in this file asks whether a server is sound. This one
// asks whether it is still the server somebody approved, which is a
// different question and the only one that can catch a change made after
// the review.
//
// It runs in the catalogue phase because that is where the catalogue is,
// and it reports nothing at all when no baseline was supplied: a check
// that invented a verdict from an absent file would be worse than no
// check.

// checkBaseline compares the catalogue against an approved snapshot.
func checkBaseline(s *Session) []Finding {
	// Taken on every run that reaches a catalogue, whether or not there is
	// anything to compare it with. The first approval has no baseline by
	// definition, so a snapshot recorded only when one already exists is a
	// snapshot that never exists the one time it is needed. It is a hash
	// over text the run already holds.
	current := baseline.Take(s.Opts.Endpoint, s.Tools)
	s.Snapshot = &current

	if s.Opts.Baseline == nil {
		return nil
	}
	c := s.check("catalog.baseline", "The catalogue is the one that was approved")

	approved := s.Opts.Baseline
	if approved.Version != baseline.Version {
		return []Finding{c.info(fmt.Sprintf(
			"the baseline was written in format %d and this passmcp reads %d; re-approve to compare",
			approved.Version, baseline.Version))}
	}

	// One string comparison answers the common case, which is what makes
	// this cheap enough to run on a schedule.
	if approved.Digest == current.Digest {
		return []Finding{c.pass(fmt.Sprintf(
			"unchanged since %s (%d tool(s))", approved.Taken.Format("2006-01-02"), len(current.Tools)))}
	}

	changes := baseline.Diff(*approved, current)
	if len(changes) == 0 {
		// The digest moved and nothing a reviewer reads did. Reported
		// rather than passed, because the honest answer is that something
		// changed in a field this check does not model.
		return []Finding{c.info("the catalogue digest changed but no reviewed field differs")}
	}

	detail := describeChanges(changes)
	fix := "read the diff and decide. If the change is intended, approve it with --approve, " +
		"which writes the current catalogue as the new baseline. If it is not, you have found " +
		"a server that changed after you reviewed it"

	switch baseline.Worst(changes) {
	case baseline.Critical:
		return []Finding{c.fail(Critical, detail, fix)}
	case baseline.Serious:
		return []Finding{c.fail(Major, detail, fix)}
	case baseline.Notable:
		return []Finding{c.warn(detail, fix)}
	default:
		// Only noise changed. Saying so is the point: a gate that cried
		// wolf over a new optional property is a gate somebody turns off.
		return []Finding{c.info(detail)}
	}
}

// describeChanges renders at most three, worst first. What changed is the
// finding, not that something did, so each one quotes both sides.
func describeChanges(changes []baseline.Change) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d change(s) since the catalogue was approved; ", len(changes))
	shown := min(len(changes), 3)
	for i := range shown {
		if i > 0 {
			b.WriteString("; ")
		}
		ch := changes[i]
		fmt.Fprintf(&b, "[%s] %s: %s", ch.Severity, ch.Tool, ch.Detail)
		if ch.Was != "" || ch.Now != "" {
			fmt.Fprintf(&b, " (was %q, now %q)", ch.Was, ch.Now)
		}
	}
	if len(changes) > shown {
		fmt.Fprintf(&b, "; and %d more", len(changes)-shown)
	}
	return b.String()
}
