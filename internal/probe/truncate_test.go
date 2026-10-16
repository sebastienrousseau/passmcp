// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"testing"
	"unicode/utf8"
)

// Server text is cut to a byte budget before it reaches a finding; a cut
// through a multi-byte character put invalid UTF-8 into every report.
func TestTruncateKeepsRunesWhole(t *testing.T) {
	for _, tc := range []struct {
		in   string
		n    int
		want string
	}{
		{"  short  ", 10, "short"},
		{"ééé", 3, "é…"},
		{"日本語のエラー", 7, "日本…"},
	} {
		got := truncate(tc.in, tc.n)
		if got != tc.want || !utf8.ValidString(got) {
			t.Errorf("truncate(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}
