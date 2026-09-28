// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"fmt"
	"sort"
	"strings"
)

// Two questions, answered by two witnesses that do not depend on each
// other: did the server go looking for credentials it was never given,
// and did anything it found leave.
//
// They are separate on purpose. The first rests on file access times,
// which a great many filesystems do not record — and where they do not,
// this reports that it cannot tell rather than that nothing happened. The
// second rests on a marker turning up somewhere it could only have come
// from the file, which works everywhere the marker is visible and is the
// stronger of the two whenever it fires.

// checkCanaries reports what the planted credentials saw.
func checkCanaries(s *Session) []Finding {
	if s.Canary == nil {
		if s.canaryErr != "" {
			return []Finding{s.check("fs.credential_probe", "The server left the planted credentials alone").
				info("the decoys could not be planted, so nothing was watched: " + s.canaryErr)}
		}
		return nil
	}
	return []Finding{probeFinding(s), exfilFinding(s)}
}

// probeFinding answers whether the decoys were opened.
func probeFinding(s *Session) Finding {
	c := s.check("fs.credential_probe", "The server left the planted credentials alone")

	usable, why := s.Canary.AtimeUsable()
	if !usable {
		// The single most important branch in this file. A check that
		// reported "clean" on a machine where it was incapable of
		// reporting anything else would be worse than no check, because
		// somebody would believe it.
		return c.skip("passmcp cannot tell whether the decoys were read here: " + why +
			". fs.canary_exfiltrated does not depend on this and still applies")
	}

	opened := s.Canary.Opened()
	if len(opened) == 0 {
		return c.pass(fmt.Sprintf("none of the %d planted credentials was opened",
			len(s.Canary.Markers())))
	}

	names := make([]string, 0, len(opened))
	for _, d := range opened {
		names = append(names, d.Name)
	}
	return c.ev(strings.Join(names, ", ")).fail(Major,
		"the server opened "+strings.Join(names, ", ")+" in its home directory",
		"a server should read the credentials it was given and no others. These files were planted "+
			"by passmcp and contain nothing real, so nothing was lost here — but the same code against "+
			"an operator's own machine reads their actual keys, and passmcp is the only thing in the "+
			"room that would have noticed")
}

// exfilFinding answers whether anything the decoys held left.
func exfilFinding(s *Session) Finding {
	c := s.check("fs.canary_exfiltrated", "Nothing planted left the machine")

	// A server that hands a planted key back to passmcp in a tool result has
	// exfiltrated it just as surely, to the only other party in the
	// conversation, so the pipe counts alongside the wire.
	seen := s.seenLeaving()

	if len(seen) == 0 {
		return c.pass("no planted credential appeared in anything the server sent")
	}

	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, n+" → "+seen[n])
	}
	return c.ev(strings.Join(parts, "; ")).fail(Critical,
		"the contents of "+strings.Join(names, ", ")+" left: "+strings.Join(parts, "; "),
		"this is not an inference. Each planted file contains a string that exists nowhere else, "+
			"and that string was seen leaving, so the file was read and its contents sent. Find "+
			"the code that did it before this server runs anywhere near a real credential")
}

// noteCanaries scans one thing the server said, as it says it.
//
// Scanned in flight rather than read back off the recorder afterwards,
// because the recorder keeps bodies only under --capture-bodies. Making
// this witness depend on an unrelated flag would mean a run that found
// nothing and a run that could not look reported the same result, which
// is the failure this whole file is arranged to avoid.
func (s *Session) noteCanaries(b []byte, where string) {
	if s.Canary == nil || len(b) == 0 {
		return
	}
	names := s.Canary.FindMarkers(string(b))
	if len(names) == 0 {
		return
	}
	s.canaryMu.Lock()
	defer s.canaryMu.Unlock()
	if s.canaryHits == nil {
		s.canaryHits = map[string]string{}
	}
	for _, n := range names {
		if _, seen := s.canaryHits[n]; !seen {
			s.canaryHits[n] = where
		}
	}
}

// seenLeaving is every decoy whose contents were observed going
// somewhere, and where to.
func (s *Session) seenLeaving() map[string]string {
	out := map[string]string{}
	if s.Proxy != nil {
		for marker, target := range s.Proxy.Escaped() {
			if name := s.Canary.MarkerName(marker); name != "" {
				out[name] = "sent to " + target
			}
		}
	}
	// What the server wrote on stderr is read at the end: it is a buffer
	// rather than a stream of events.
	if s.Pipe != nil {
		for _, n := range s.Canary.FindMarkers(s.Pipe.Stderr()) {
			if _, already := out[n]; !already {
				out[n] = "written to the server's own stderr"
			}
		}
	}
	s.canaryMu.Lock()
	defer s.canaryMu.Unlock()
	for n, where := range s.canaryHits {
		if _, already := out[n]; !already {
			out[n] = where
		}
	}
	return out
}
