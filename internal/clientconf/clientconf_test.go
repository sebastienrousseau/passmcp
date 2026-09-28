// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package clientconf

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func mustParse(t *testing.T, src string) *Config {
	t.Helper()
	c, err := Parse("mcp.json", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return c
}

func server(t *testing.T, c *Config, name string) Server {
	t.Helper()
	for _, s := range c.Servers {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no server %q in %+v", name, c.Servers)
	return Server{}
}

func TestParseClaudeLayoutKeepsLines(t *testing.T) {
	c := mustParse(t, `{
  "mcpServers": {
    "files": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem@1.2.3"
      ],
      "env": {"API_TOKEN": "s3cret-value"}
    },
    "remote": {"url": "https://mcp.example.test/mcp", "headers": {"Authorization": "Bearer abc"}}
  }
}`)
	if c.Format != "claude" || len(c.Servers) != 2 {
		t.Fatalf("format %q, %d servers", c.Format, len(c.Servers))
	}
	f := server(t, c, "files")
	if !f.Stdio() || f.Line != 3 || f.CommandLine != 4 || !slices.Equal(f.ArgLines, []int{6, 7}) {
		t.Fatalf("files: %+v", f)
	}
	if f.Describe() != "npx -y @modelcontextprotocol/server-filesystem@1.2.3" {
		t.Fatalf("describe %q", f.Describe())
	}
	if !slices.Equal(f.EnvNames, []string{"API_TOKEN"}) {
		t.Fatalf("env names %v", f.EnvNames)
	}
	r := server(t, c, "remote")
	if r.Stdio() || r.Describe() != "https://mcp.example.test/mcp" || !slices.Equal(r.HeaderNames, []string{"Authorization"}) {
		t.Fatalf("remote: %+v", r)
	}
	sec := c.Secrets()
	if !slices.Contains(sec, "s3cret-value") || !slices.Contains(sec, "Bearer abc") {
		t.Fatalf("secrets %v", sec)
	}
}

func TestParseVSCodeAndZedLayouts(t *testing.T) {
	vs := mustParse(t, `// .vscode/mcp.json
{
  /* the servers */
  "servers": {
    "gh": {"type": "stdio", "command": "uvx", "args": ["mcp-gh==1.0"],}, // trailing comma
  },
}`)
	if vs.Format != "vscode" || server(t, vs, "gh").Line != 5 {
		t.Fatalf("vscode: %+v", vs)
	}
	settings := mustParse(t, `{"mcp": {"servers": {"a": {"serverUrl": "https://a.test/mcp"}}}}`)
	if settings.Format != "vscode" || server(t, settings, "a").URL != "https://a.test/mcp" {
		t.Fatalf("settings: %+v", settings)
	}
	zed := mustParse(t, `{
  "context_servers": {
    "z": {
      "command": {
        "path": "npx",
        "args": ["zed-mcp"],
        "env": {"K": "v"}
      }
    }
  }
}`)
	z := server(t, zed, "z")
	if zed.Format != "zed" || z.Command != "npx" || z.CommandLine != 5 || !slices.Equal(z.ArgLines, []int{6}) || z.Env["K"] != "v" {
		t.Fatalf("zed: %+v", z)
	}
}

func TestParseKeepsCommentLookalikesInStrings(t *testing.T) {
	c := mustParse(t, `{"mcpServers": {"u": {"url": "https://x.test/a//b/*c*/", "headers": {"X": "a\",}"}}}}`)
	if u := server(t, c, "u"); u.URL != "https://x.test/a//b/*c*/" || u.Headers["X"] != `a",}` {
		t.Fatalf("strings altered: %+v", u)
	}
}

func TestParseErrors(t *testing.T) {
	for name, src := range map[string]string{
		"not json":        `{`,
		"no servers":      `{"editor": {}}`,
		"servers not obj": `{"mcpServers": []}`,
		"empty entry":     `{"mcpServers": {"x": {}}}`,
		"bad command":     `{"mcpServers": {"x": {"command": 3}}}`,
		"bad entry":       `{"mcpServers": {"x": []}}`,
	} {
		if _, err := Parse("c.json", []byte(src)); err == nil {
			t.Errorf("%s: parsed", name)
		} else if !strings.Contains(err.Error(), "c.json") {
			t.Errorf("%s: error does not name the file: %v", name, err)
		}
	}
	var nilCfg *Config
	if nilCfg.Secrets() != nil || nilCfg.Audit() != nil {
		t.Fatal("nil config yields something")
	}
}

func TestLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "claude_desktop_config.json")
	if err := os.WriteFile(p, []byte(`{"mcpServers": {"a": {"command": "srv"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil || c.Path != p || len(c.Servers) != 1 {
		t.Fatalf("Load: %v %+v", err, c)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing file loaded")
	}
}

func TestStripJSONCEdges(t *testing.T) {
	out := stripJSONC([]byte("{\n/* open\ncomment"))
	if strings.Contains(string(out), "open") || strings.Count(string(out), "\n") != 2 {
		t.Fatalf("got %q", out)
	}
	if closesNext([]byte("   "), 0) {
		t.Fatal("closesNext on blank")
	}
}
