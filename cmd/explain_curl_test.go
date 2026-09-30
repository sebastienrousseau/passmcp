// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// realBearer is a token the fake server accepts. It is what a report made
// with a real credential carries in its requests, and what no reproducer
// may contain.
const realBearer = "tok-REAL-bearer-0123456789abcdef"

// bearerReport runs a check with a real bearer token, bodies captured and
// events embedded, and writes the JSON report to a file.
func bearerReport(t *testing.T, extra ...string) (*fakeServer, string) {
	t.Helper()
	f := newFakeServer(t)
	f.mu.Lock()
	f.tokens[realBearer] = true
	f.mu.Unlock()
	args := append([]string{"check", f.srv.URL + "/mcp", "--auth", "bearer", "--token", realBearer,
		"--output", "json", "--events", "--phases", "net,discovery,auth,handshake,protocol"}, fastFlags()...)
	out, code := run(t, append(args, extra...)...)
	if code > 2 {
		t.Fatalf("the check failed outright (exit %d)", code)
	}
	if strings.Contains(out, realBearer) {
		t.Fatal("the report itself carries the token; the recorder is broken, not the reproducer")
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	return f, path
}

// TestExplainCurlNeverCarriesTheBearerToken is the redaction proof: a
// report produced with a real bearer token yields a curl command with the
// placeholder where the token went, and never the token.
func TestExplainCurlNeverCarriesTheBearerToken(t *testing.T) {
	_, path := bearerReport(t, "--capture-bodies")
	out, code := run(t, "explain", path, "--curl", "protocol.ping")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if strings.Contains(out, realBearer) {
		t.Fatalf("the reproducer carries the bearer token:\n%s", out)
	}
	for _, want := range []string{"curl -sS -X 'POST'", `'Authorization: Bearer '"${PASSMCP_TOKEN}"`, "--data-raw", `"method":"ping"`, "#   PASSMCP_TOKEN", "protocol.ping", "req#"} {
		if !strings.Contains(out, want) {
			t.Errorf("reproducer lacks %s:\n%s", want, out)
		}
	}
}

// TestExplainCurlReproducesTheRequest: run what it printed, with the
// token exported, against the server the report was made against, and
// get the answer the check got.
func TestExplainCurlReproducesTheRequest(t *testing.T) {
	sh, errSh := exec.LookPath("sh")
	_, errCurl := exec.LookPath("curl")
	if errSh != nil || errCurl != nil || runtime.GOOS == "windows" {
		t.Skip("needs sh and curl")
	}
	_, path := bearerReport(t, "--capture-bodies")
	out, code := run(t, "explain", path, "--curl", "protocol.ping")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	cmd := exec.Command(sh, "-c", out)
	cmd.Env = append(os.Environ(), "PASSMCP_TOKEN="+realBearer)
	got, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the reproducer did not run: %v\n%s\n%s", err, out, got)
	}
	if !strings.Contains(string(got), `"result":{}`) {
		t.Errorf("the server did not answer the reproduced ping:\n%s", got)
	}
}

// TestExplainCurlJSON gives the same commands as data.
func TestExplainCurlJSON(t *testing.T) {
	_, path := bearerReport(t)
	out, code := run(t, "explain", path, "--curl", "handshake.initialize", "--output", "json")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	var repros []struct {
		ID        string   `json:"id"`
		Seq       int      `json:"seq"`
		Curl      string   `json:"curl"`
		Variables []string `json:"variables"`
		Notes     []string `json:"notes"`
	}
	if err := json.Unmarshal([]byte(out), &repros); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if len(repros) != 2 || repros[0].ID != "handshake.initialize" || repros[0].Seq == 0 {
		t.Fatalf("repros = %+v", repros)
	}
	// Bodies were not captured, so the reproducer says so rather than
	// inventing one.
	if len(repros[0].Notes) == 0 || !strings.Contains(repros[0].Notes[0], "--capture-bodies") {
		t.Errorf("notes = %v", repros[0].Notes)
	}
	if strings.Contains(out, realBearer) {
		t.Error("the JSON reproducer carries the bearer token")
	}
}

// TestExplainCurlRefusesWhatItCannotReproduce: exit 1 and nothing on
// stdout, so a script that pipes it into sh runs nothing.
func TestExplainCurlRefusesWhatItCannotReproduce(t *testing.T) {
	_, path := bearerReport(t)
	_, reportJSON, _ := attestFixture(t)
	noEvents := writeTemp(t, "report.json", reportJSON)
	for _, args := range [][]string{
		{"explain", path, "--curl", "no.such.check"},
		{"explain", path, "--curl", "net.scheme"},
		{"explain", noEvents, "--curl", "protocol.ping"},
	} {
		if out, code := run(t, args...); code != 1 || out != "" {
			t.Errorf("%v: exit %d, stdout %q", args[2:], code, out)
		}
	}
}
