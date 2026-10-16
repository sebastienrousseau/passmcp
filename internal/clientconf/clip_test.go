// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package clientconf

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// A long command line with non-ASCII arguments was cut through a
// character, leaving invalid UTF-8 in the finding.
func TestClipKeepsRunesWhole(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"npx  server", "npx server"},
		{strings.Repeat("a", 79) + "é", strings.Repeat("a", 79) + "…"},
		{strings.Repeat("é", 50), strings.Repeat("é", 40) + "…"},
	} {
		got := clip(tc.in)
		if got != tc.want || !utf8.ValidString(got) {
			t.Errorf("clip(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
