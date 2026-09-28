// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package auth

import "testing"

func BenchmarkParseWWWAuthenticate(b *testing.B) {
	h := `Basic realm="x", Bearer realm="mcp", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp", scope="a b c", error="insufficient_scope"`
	for i := 0; i < b.N; i++ {
		ParseWWWAuthenticate(h)
	}
}
