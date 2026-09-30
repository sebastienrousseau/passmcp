// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package termsafe

import (
	"bytes"
	"testing"
)

// FuzzString holds the properties a terminal depends on for any input a
// server could send: nothing that can start a control sequence survives,
// cleaning twice changes nothing, and the Writer agrees with String
// however the input is split between writes.
func FuzzString(f *testing.F) {
	for _, seed := range []string{
		"plain", "\x1b[31mred", "\x1b]0;t\x07x", "\xc2\x9b2J", "\xc2\x1b[0m\x9b",
		"\x1bP\x1b\\", "a\rb", "café", "\x1b]8;;u\x1b\\l",
	} {
		f.Add(seed, 3)
	}
	f.Fuzz(func(t *testing.T, in string, split int) {
		out := String(in)
		for i := 0; i < len(out); i++ {
			b := out[i]
			if (b < 0x20 && b != '\n' && b != '\t') || b == 0x7f {
				t.Fatalf("control byte %#x survived in %q", b, out)
			}
			if b == 0xc2 && (i+1 >= len(out) || out[i+1] < 0xa0 || out[i+1] > 0xbf) {
				t.Fatalf("C1 control or stray lead byte survived at %d in %q", i, out)
			}
		}
		if again := String(out); again != out {
			t.Fatalf("not idempotent: %q then %q", out, again)
		}
		var buf bytes.Buffer
		w := NewWriter(&buf)
		cut := 0
		if len(in) > 0 {
			cut = (split%len(in) + len(in)) % len(in)
		}
		_, _ = w.Write([]byte(in[:cut]))
		_, _ = w.Write([]byte(in[cut:]))
		if buf.String() != out {
			t.Fatalf("writer split at %d gave %q, String gave %q", cut, buf.String(), out)
		}
	})
}
