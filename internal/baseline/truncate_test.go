// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package baseline

import (
	"testing"
	"unicode/utf8"
)

// A tool description cut through a multi-byte character made the change
// list invalid UTF-8.
func TestTruncateKeepsRunesWhole(t *testing.T) {
	for _, tc := range []struct {
		in   string
		n    int
		want string
	}{
		{"one\n two", 10, "one two"},
		{"ééé", 3, "é…"},
		{"Récupère  les données", 2, "R…"},
	} {
		got := truncate(tc.in, tc.n)
		if got != tc.want || !utf8.ValidString(got) {
			t.Errorf("truncate(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}
