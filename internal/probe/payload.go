// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"fmt"
	"sort"
	"strings"
)

// The catalogue budget measures what a server costs to look at. This
// measures what it costs to use.
//
// A tool result is not a file somebody downloads. It goes into the model's
// context, whole, on the call that asked for it — so a tool that answers
// with a hundred kilobytes has spent a quarter of a small window on one
// reply, and a tool that answers with a megabyte has ended the
// conversation. The caller cannot refuse delivery: by the time the size is
// known it has already arrived.
//
// What separates a large answer from a broken one is whether the server
// knows it is large. A result that paginates, truncates, or says it was
// cut is a server that thought about this. A result that is simply
// enormous is one that did not, and the difference is visible in the text.
//
// Nothing here costs a request. The execution phase already called these
// tools and already counted the bytes.

// Payload sizes, in bytes of text handed to the model.
const (
	// payloadNotable is roughly an eighth of a small context window once
	// tokenised, from a single call. Worth a reader knowing.
	payloadNotable = 64 << 10 // 64 KiB
	// payloadTrouble is where one answer stops leaving room for the
	// conversation it was part of.
	payloadTrouble = 512 << 10 // 512 KiB
)

// boundedHints are the words a server uses when it knows its answer was
// cut. Finding one is the difference between a big result and a runaway
// one, so the list is deliberately generous: a false positive here only
// costs a warning that was not raised, and the size is still reported.
var boundedHints = []string{
	"truncated", "truncation", "has been cut", "was cut",
	"next_cursor", "nextcursor", "next_page", "nextpage",
	"has_more", "hasmore", "page_token", "pagetoken",
	"showing first", "showing the first", "results omitted",
	"omitted for brevity", "see more", "remaining results",
}

// checkPayloadSize reports what the largest answer cost the caller.
func checkPayloadSize(s *Session) []Finding {
	c := s.check("execution.payload_size", "Results leave room for the conversation")

	type result struct {
		name  string
		bytes int
	}
	var seen []result
	for _, tr := range s.ToolResults {
		if tr.OK && tr.TextBytes > 0 {
			seen = append(seen, result{tr.Name, tr.TextBytes})
		}
	}
	if len(seen) == 0 {
		// No successful call means no answer to weigh. Saying so beats
		// passing a check that measured nothing.
		return []Finding{c.skip("no tool returned content, so there was nothing to weigh")}
	}
	sort.SliceStable(seen, func(i, j int) bool { return seen[i].bytes > seen[j].bytes })
	largest := seen[0]

	if largest.bytes < payloadNotable {
		return []Finding{c.pass(fmt.Sprintf("largest result %s, from %s",
			humanBytes(largest.bytes), largest.name))}
	}

	// Large is not the same as unbounded. A server that says it cut the
	// answer has thought about this, and reporting it as a defect is how
	// a check gets ignored by the people who did the work.
	bounded := saysItIsBounded(s, largest.name)
	detail := fmt.Sprintf("largest result %s, from %s; every byte of it goes into the model's context on the call that asked",
		humanBytes(largest.bytes), largest.name)

	switch {
	case bounded:
		return []Finding{c.info(detail + ". The result says it was paginated or truncated, so the size is a choice rather than an accident")}
	case largest.bytes >= payloadTrouble:
		return []Finding{c.warn(detail+", and nothing in it suggests it was paginated or truncated",
			"bound the result. A caller cannot refuse delivery — by the time the size is known the "+
				"answer has already arrived and the window has already been spent. Page it, truncate "+
				"it with a note saying so, or return a handle the caller can fetch in parts")}
	default:
		return []Finding{c.info(detail + ", with no sign of pagination or truncation")}
	}
}

// saysItIsBounded reports whether the tool's own answer admits to being
// cut short.
func saysItIsBounded(s *Session, tool string) bool {
	for _, tr := range s.ToolResults {
		if tr.Name != tool {
			continue
		}
		// Only what this run actually saw: the schema issues carry the
		// result's shape, and the tool's own description says whether
		// paging was ever on offer.
		hay := strings.ToLower(strings.Join(tr.SchemaIssues, " ") + " " + tr.ToolError)
		for _, hint := range boundedHints {
			if strings.Contains(hay, hint) {
				return true
			}
		}
	}
	// The catalogue is the other place a server declares it. A tool whose
	// schema names a cursor is one that expects to be called again.
	for _, t := range s.Tools {
		if t.Name != tool {
			continue
		}
		hay := strings.ToLower(string(t.InputSchema) + " " + string(t.OutputSchema) + " " + t.Description)
		for _, hint := range boundedHints {
			if strings.Contains(hay, hint) {
				return true
			}
		}
	}
	return false
}
