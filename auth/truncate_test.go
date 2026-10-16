// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package auth

import (
	"testing"
	"unicode/utf8"
)

// A registration error body is quoted in the error up to a byte budget; a
// cut through a multi-byte character made the error invalid UTF-8.
func TestTruncateKeepsRunesWhole(t *testing.T) {
	for _, tc := range []struct {
		in   string
		n    int
		want string
	}{
		{"short", 10, "short"},
		{"ééé", 3, "é..."},
		{"错误：无效的客户端", 8, "错误..."},
		{"\xff\xff\xff", 2, "\xff\xff..."}, // not UTF-8: cut at the budget
	} {
		got := truncate([]byte(tc.in), tc.n)
		if got != tc.want || (utf8.ValidString(tc.in) && !utf8.ValidString(got)) {
			t.Errorf("truncate(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}
