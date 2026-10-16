// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package telemetry

import (
	"slices"
	"strings"
)

// maskSet masks a list of patterns in priority order: each pattern in turn
// is replaced with Mask by strings.ReplaceAll, and the replacements are
// counted. That is the redactor's masking rule, and its result depends on
// the order when patterns overlap, so it is kept exactly.
//
// What is avoided is the cost. Replacing a thousand registered tokens one
// at a time scans every body a thousand times, although almost none of the
// tokens occur in it. So a large set first finds, in one pass, which
// patterns occur anywhere in the text, and replaces only those, in order.
// That is exact: a replacement only removes text and inserts Mask, so a
// pattern that does not occur in the original can occur later only by
// spanning a Mask, which needs the mask's own character. Patterns that
// contain it are therefore always replaced, found or not.
//
// Patterns are added in groups (a secret and its URL-escaped form) that
// keep their internal order and are placed by group index.
type maskSet struct {
	// groups hold pattern ids in priority order; byID maps an id, which
	// never changes, to its pattern, and star marks the ids whose pattern
	// contains the mask's character.
	groups [][]int
	byID   []string
	star   []bool
	// first holds every pattern id under its pattern's first byte, and
	// pairs has a bit set for every pattern's first two bytes, so most
	// positions in a text are rejected by one bit test.
	first [256][]int
	pairs [1 << 16 / 64]uint64
}

// seqMax is how many patterns are cheaper to replace one scan at a time:
// a scan for one pattern is vectorised, the pass that finds every pattern
// is not.
const seqMax = 16

// insert places group at index at among the groups.
func (m *maskSet) insert(at int, group []string) {
	ids := make([]int, len(group))
	for i, p := range group {
		ids[i] = m.index(p)
	}
	m.groups = slices.Insert(m.groups, at, ids)
}

// index gives p an id and enters it in the lookup tables.
func (m *maskSet) index(p string) int {
	id := len(m.byID)
	m.byID = append(m.byID, p)
	// Every pattern is at least two bytes; one shorter is replaced
	// unconditionally rather than looked up.
	m.star = append(m.star, strings.Contains(p, Mask[:1]) || len(p) < 2)
	if len(p) >= 2 {
		m.first[p[0]] = append(m.first[p[0]], id)
		k := uint16(p[0])<<8 | uint16(p[1])
		m.pairs[k/64] |= 1 << (k % 64)
	}
	return id
}

// apply masks every pattern in s and reports how many replacements it
// made.
func (m *maskSet) apply(s string) (string, int) {
	var found []bool
	if len(m.byID) > seqMax {
		found = m.find(s)
	}
	n := 0
	for _, g := range m.groups {
		for _, id := range g {
			if found != nil && !found[id] && !m.star[id] {
				continue
			}
			var c int
			s, c = replaceCounting(s, m.byID[id])
			n += c
		}
	}
	return s, n
}

// replaceCounting replaces every p in s with Mask, as strings.ReplaceAll
// does, and reports how many it replaced. Each replacement changes the
// length by the same amount, so the count costs nothing unless p is as
// long as Mask.
func replaceCounting(s, p string) (string, int) {
	if len(p) == len(Mask) {
		c := strings.Count(s, p)
		if c > 0 {
			s = strings.ReplaceAll(s, p, Mask)
		}
		return s, c
	}
	out := strings.ReplaceAll(s, p, Mask)
	return out, (len(s) - len(out)) / (len(p) - len(Mask))
}

// find reports, by pattern id, which patterns occur anywhere in s,
// overlapping occurrences included. It never returns nil.
func (m *maskSet) find(s string) []bool {
	found := make([]bool, len(m.byID))
	for i := 0; i+1 < len(s); i++ {
		k := uint16(s[i])<<8 | uint16(s[i+1])
		if m.pairs[k/64]&(1<<(k%64)) == 0 {
			continue
		}
		for _, id := range m.first[s[i]] {
			if !found[id] && strings.HasPrefix(s[i:], m.byID[id]) {
				found[id] = true
			}
		}
	}
	return found
}
