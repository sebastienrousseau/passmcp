// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package auth

import "testing"

func TestParseWWWAuthenticate(t *testing.T) {
	cases := []struct {
		in     string
		scheme string
		want   map[string]string
		n      int
	}{
		{`Bearer realm="mcp", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"`,
			"Bearer", map[string]string{"realm": "mcp", "resource_metadata": "https://api.example.com/.well-known/oauth-protected-resource"}, 1},
		{`Bearer resource_metadata=https://x.example/prm,scope="a b"`,
			"Bearer", map[string]string{"resource_metadata": "https://x.example/prm", "scope": "a b"}, 1},
		{`Basic realm="x", Bearer error="insufficient_scope", scope="files:write", error_description="need \"more\""`,
			"Bearer", map[string]string{"error": "insufficient_scope", "scope": "files:write", "error_description": `need "more"`}, 2},
		{`Bearer`, "Bearer", map[string]string{}, 1},
		{`Negotiate abc==, Bearer realm="r"`, "Bearer", map[string]string{"realm": "r"}, 2},
		{`  Bearer   RESOURCE_METADATA = "https://u"  `, "Bearer", map[string]string{"resource_metadata": "https://u"}, 1},
	}
	for _, c := range cases {
		got := ParseWWWAuthenticate(c.in)
		if len(got) != c.n {
			t.Errorf("%q: got %d challenges, want %d: %+v", c.in, len(got), c.n, got)
			continue
		}
		b, ok := FindBearer(got)
		if !ok {
			t.Errorf("%q: no bearer", c.in)
			continue
		}
		for k, v := range c.want {
			if b.Params[k] != v {
				t.Errorf("%q: param %s = %q, want %q", c.in, k, b.Params[k], v)
			}
		}
	}
}

func TestParseWWWAuthenticateGarbage(t *testing.T) {
	for _, in := range []string{"", ",,,", `Bearer realm="unterminated`, `=`, `Bearer =x`} {
		_ = ParseWWWAuthenticate(in) // must not panic
	}
}
