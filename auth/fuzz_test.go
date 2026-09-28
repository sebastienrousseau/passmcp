// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package auth

import "testing"

func FuzzParseWWWAuthenticate(f *testing.F) {
	for _, s := range []string{
		`Bearer realm="mcp", resource_metadata="https://x/.well-known/oauth-protected-resource"`,
		`Basic realm="x", Bearer error="insufficient_scope", scope="a b"`,
		`Negotiate abc==, Bearer`, `Bearer resource_metadata=https://x/prm,scope=a`, ``, `,,,`, `Bearer realm="unterminated`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, c := range ParseWWWAuthenticate(s) {
			if c.Scheme == "" {
				t.Fatalf("empty scheme from %q", s)
			}
		}
	})
}
