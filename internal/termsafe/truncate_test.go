// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package termsafe

import (
	"testing"
	"unicode/utf8"
)

func TestTruncateCutsOnARuneBoundary(t *testing.T) {
	for _, tc := range []struct {
		in   string
		n    int
		want string
	}{
		{"abc", 3, "abc"},   // fits: untouched, no mark
		{"abcd", 3, "abc…"}, // ASCII: the byte budget exactly
		{"ééé", 3, "é…"},    // é is two bytes: never half of one
		{"ééé", 4, "éé…"},   // a budget that ends on a boundary
		{"a€b", 2, "a…"},    // three-byte rune
		{"a😀b", 4, "a…"},    // four-byte rune
		{"😀😀", 1, "…"},      // nothing whole fits
		{"\x80\x80\x80\x80\x80\x80", 5, "\x80\x80\x80\x80\x80…"}, // invalid input: cut at the budget, no backtracking past it
		{"", 0, ""},
	} {
		got := Truncate(tc.in, tc.n, "…")
		if got != tc.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
		if utf8.ValidString(tc.in) && !utf8.ValidString(got) {
			t.Errorf("Truncate(%q, %d) = %q is not valid UTF-8", tc.in, tc.n, got)
		}
	}
}
