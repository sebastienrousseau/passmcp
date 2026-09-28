// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"fmt"
	"time"

	"satellion.com/passmcp"
)

// The catalogue budget check says what a catalogue costs to look at. This
// one says whether the server did anything about it.
//
// A catalogue is fetched again by every client, on every session, and then
// paid for in context on every call after that. The 2026-07-28 revision
// answers that directly: any list result may carry `ttlMs`, how long a
// client may keep it, and `cacheScope`, whether that cache may be shared
// between users. A server that states them lets a client stop re-fetching
// a catalogue it already has.
//
// Two things keep this honest. Both fields are optional, so their absence
// is a missed opportunity and not a violation — it is reported as a
// warning only on a catalogue large enough for the re-fetch to cost
// something, and as an observation otherwise. And they do not exist before
// 2026-07-28 at all, so a session-era server is not asked about them: it
// would be a finding about the revision the operator is running, not about
// the server.

// cacheHintFloor is the catalogue size, in the same estimated tokens the
// budget check uses, above which saying nothing about caching is worth a
// warning rather than a note.
//
// Set at the budget's own warn threshold so the two cannot disagree: the
// point at which a catalogue stops being free is the point at which
// re-fetching it starts to matter.
const cacheHintFloor = CatalogueTokenBudget

// checkCacheHints reports what the server said about caching its
// catalogue.
func checkCacheHints(s *Session, hints passmcp.CacheHints, tokens int) []Finding {
	c := s.check("catalog.cache_hints", "The catalogue says whether it can be cached")

	// Before 2026-07-28 there are no such fields to state.
	if s.Era == nil || s.Era.Era != passmcp.EraStateless {
		return []Finding{c.skip("cache hints on a list result arrived in the 2026-07-28 revision; " +
			"this server speaks an earlier one, where there is nothing to state")}
	}

	if hints.Stated() {
		var detail string
		switch {
		case hints.TTLMs != nil && hints.Scope != "":
			detail = fmt.Sprintf("cacheable for %s, scope %q",
				time.Duration(*hints.TTLMs)*time.Millisecond, hints.Scope)
		case hints.TTLMs != nil:
			detail = fmt.Sprintf("cacheable for %s; no cacheScope, so a client must assume private",
				time.Duration(*hints.TTLMs)*time.Millisecond)
		default:
			detail = fmt.Sprintf("cacheScope %q, but no ttlMs, so a client is told how it may share "+
				"the answer and not for how long", hints.Scope)
		}
		return []Finding{c.pass(detail)}
	}

	const advice = "set ttlMs on the tools/list result, and cacheScope when the catalogue is the same " +
		"for every user. A catalogue is re-fetched on every session and then costs context on every " +
		"call; these two fields are the protocol's own way to stop the first half of that"

	if tokens >= cacheHintFloor {
		return []Finding{c.warn(fmt.Sprintf(
			"neither ttlMs nor cacheScope, on a catalogue of about %d tokens that every client "+
				"re-fetches each session", tokens), advice)}
	}
	return []Finding{c.info("neither ttlMs nor cacheScope; the catalogue is small enough that " +
		"re-fetching it is cheap, so this is an opportunity rather than a cost")}
}
