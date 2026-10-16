// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package termsafe

import "unicode/utf8"

// Truncate shortens s to at most n bytes and appends mark, or returns s
// unchanged when it already fits. The budget is in bytes, as the callers'
// limits always were, but the cut lands on a rune boundary: slicing a
// string at a byte offset can split a multi-byte character and leave
// invalid UTF-8 in a report, a terminal or a JSON document.
//
// Input that is not valid UTF-8 where the cut falls is cut at n, since it
// has no boundary to respect.
func Truncate(s string, n int, mark string) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for i := n; i >= 0 && i > n-utf8.UTFMax; i-- {
		if utf8.RuneStart(s[i]) {
			cut = i
			break
		}
	}
	return s[:cut] + mark
}
