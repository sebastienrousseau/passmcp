// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import (
	"bytes"
	"strings"
	"testing"
)

// blankLine must agree with the string test it replaced, Unicode spaces
// and invalid UTF-8 included.
func TestBlankLineMatchesStrings(t *testing.T) {
	for _, in := range []string{"", " ", " \t\r\n", "\u00a0\u2028\u3000", "\u00a0x", "\xff", " \xc2", "{}", "\x85"} {
		if got, want := blankLine([]byte(in)), len(strings.TrimSpace(in)) == 0; got != want {
			t.Errorf("blankLine(%q) = %t, want %t", in, got, want)
		}
	}
}

// BenchmarkBlankLine tests a 1 MiB message for blankness, as the stdio
// reader does for every line it reads.
func BenchmarkBlankLine(b *testing.B) {
	line := append([]byte(`{"jsonrpc":"2.0","id":1,"result":{"text":"`), bytes.Repeat([]byte("x"), 1<<20)...)
	line = append(line, `"}}`...)
	b.SetBytes(int64(len(line)))
	for i := 0; i < b.N; i++ {
		if blankLine(line) {
			b.Fatal("not blank")
		}
	}
}
