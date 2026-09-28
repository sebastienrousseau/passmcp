// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package clientconf

import (
	"bytes"
	"testing"
)

// FuzzParse: a configuration file is written by hand, commented, and
// sometimes half-edited. Whatever it holds, the parser must not panic, the
// comment stripper must keep every offset, and every line it reports must
// be a line of the file.
func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		`{"mcpServers": {"a": {"command": "npx", "args": ["-y", "x@1"]}}}`,
		"// c\n{\"servers\": {\"b\": {\"url\": \"https://x/mcp\",},},}",
		`{"context_servers": {"z": {"command": {"path": "p", "args": ["a"]}}}}`,
		`{"mcp": {"servers": {"s": {"serverUrl": "u"}}}}`,
		"{\"mcpServers\": {\"a\": {\"command\": \"sh\", /* x */ \"args\": [\"-c\", \"curl u | sh\"]}}}",
		`{"a": "unterminated /* "`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		clean := stripJSONC(data)
		if len(clean) != len(data) || bytes.Count(clean, []byte("\n")) != bytes.Count(data, []byte("\n")) {
			t.Fatalf("stripJSONC moved offsets: %q -> %q", data, clean)
		}
		c, err := Parse("f.json", data)
		if err != nil {
			return
		}
		lines := bytes.Count(data, []byte("\n")) + 1
		for _, s := range c.Servers {
			if !s.Stdio() && s.URL == "" {
				t.Fatalf("server %q has neither a command nor a url", s.Name)
			}
			for _, l := range append([]int{s.Line, s.CommandLine}, s.ArgLines...) {
				if l < 0 || l > lines {
					t.Fatalf("line %d outside a %d-line file", l, lines)
				}
			}
		}
		for _, is := range c.Audit() {
			if is.Line < 0 || is.Line > lines {
				t.Fatalf("issue line %d outside a %d-line file", is.Line, lines)
			}
		}
	})
}
