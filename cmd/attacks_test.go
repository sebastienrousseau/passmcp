// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// AC: ATK-06
// TestClientConfigFlagReadsTheLaunchCommands, through the CLI: the file
// named by --client-config reaches the run, and its launch commands are
// reported with the line that carries each issue.
func TestClientConfigFlagReadsTheLaunchCommands(t *testing.T) {
	f := newFakeServer(t)
	path := filepath.Join(t.TempDir(), "claude_desktop_config.json")
	body := "{\n  \"mcpServers\": {\n    \"fs\": {\"command\": \"npx\", \"args\": [\"-y\", \"@acme/fs-server\"]}\n  }\n}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _ := run(t, baselineArgs(f.srv.URL+"/mcp", "--client-config", path, "--output", "json")...)
	// The JSON report escapes the path, and a Windows path has backslashes.
	where, _ := json.Marshal(path + ":3")
	if !strings.Contains(out, `"stdio.launch_config"`) || !strings.Contains(out, strings.Trim(string(where), `"`)) {
		t.Errorf("the launch configuration was not reported with its line:\n%s", out)
	}
}

// AC: ATK-01
// TestClientConfigFlagRejectsAFileThatIsNotOne: a typo must not become a
// run that silently compared nothing.
func TestClientConfigFlagRejectsAFileThatIsNotOne(t *testing.T) {
	f := newFakeServer(t)
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"editor.fontSize": 12}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := runCapturingStderr(t, baselineArgs(f.srv.URL+"/mcp", "--client-config", path)...)
	if code == 0 {
		t.Fatalf("a file naming no servers was accepted:\n%s\n%s", out, errOut)
	}
}

// AC: ATK-04
// TestWrongAudienceFlagSendsTheNamedToken: the variable's value is sent
// and the report says what the server did with it, never the value.
func TestWrongAudienceFlagSendsTheNamedToken(t *testing.T) {
	f := newFakeServer(t)
	t.Setenv("PASSMCP_TEST_WRONG_AUD", "token-minted-for-elsewhere")
	out, _ := run(t, baselineArgs(f.srv.URL+"/mcp", "--wrong-audience-token-env", "PASSMCP_TEST_WRONG_AUD", "--output", "json")...)
	if !strings.Contains(out, `"auth.wrong_audience"`) {
		t.Errorf("auth.wrong_audience missing:\n%s", out)
	}
	if strings.Contains(out, "token-minted-for-elsewhere") {
		t.Error("the token's value reached the report")
	}
}
