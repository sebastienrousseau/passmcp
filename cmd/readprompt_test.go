// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/engine"
)

// clientCreds are the flags that get through the fake server's
// authorization server.
func clientCreds() []string {
	return []string{"--auth", "client-credentials", "--client-id", "cid", "--client-secret", "sec", "--param", "profile_id=t1", "--log-level", "error"}
}

// TestReadPrintsTheResource, through the fake server's OAuth, the way call
// reaches a tool.
func TestReadPrintsTheResource(t *testing.T) {
	f := newFakeServer(t)
	out, code := run(t, append([]string{"read", f.srv.URL + "/mcp", "fake://doc/1"}, clientCreds()...)...)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, want := range []string{"fake://doc/1 ok in", "hello"} {
		if !strings.Contains(out, want) {
			t.Errorf("read text lacks %q:\n%s", want, out)
		}
	}
	assertNothingInvoked(t, f)
}

// TestReadJSONCarriesTheResultAndNoSecret. The telemetry summary rides
// along, and nothing the run was given or issued may.
func TestReadJSONCarriesTheResultAndNoSecret(t *testing.T) {
	f := newFakeServer(t)
	out, code := run(t, append([]string{"read", f.srv.URL + "/mcp", "fake://doc/1", "--output", "json"}, clientCreds()...)...)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	var doc struct {
		URI        string   `json:"uri"`
		DurationMS *float64 `json:"duration_ms"`
		Result     passmcp.ReadResourceResult
		Telemetry  struct{ Requests int }
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if doc.URI != "fake://doc/1" || doc.DurationMS == nil || len(doc.Result.Contents) != 1 || doc.Telemetry.Requests == 0 {
		t.Errorf("document = %+v", doc)
	}
	assertNoIssuedSecret(t, f, out)
}

// TestPromptRendersTheMessages with the arguments given.
func TestPromptRendersTheMessages(t *testing.T) {
	f := newFakeServer(t)
	out, code := run(t, append([]string{"prompt", f.srv.URL + "/mcp", "summarise", "--arg", "doc=report"}, clientCreds()...)...)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, want := range []string{"summarise ok in", "[user] Summarise"} {
		if !strings.Contains(out, want) {
			t.Errorf("prompt text lacks %q:\n%s", want, out)
		}
	}
	assertNothingInvoked(t, f)
}

// TestPromptJSONEchoesTheArguments, so a saved result says what it was
// rendered with.
func TestPromptJSONEchoesTheArguments(t *testing.T) {
	f := newFakeServer(t)
	out, code := run(t, append([]string{"prompt", f.srv.URL + "/mcp", "summarise", "--arg", "doc=a=b", "--output", "json"}, clientCreds()...)...)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	var doc struct {
		Prompt    string            `json:"prompt"`
		Arguments map[string]string `json:"arguments"`
		Result    passmcp.GetPromptResult
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if doc.Prompt != "summarise" || doc.Arguments["doc"] != "a=b" || len(doc.Result.Messages) != 1 {
		t.Errorf("document = %+v", doc)
	}
	assertNoIssuedSecret(t, f, out)
}

// TestReadAndPromptRefuseWhatTheyCannotRun: every refusal is exit 1 with
// nothing on stdout, as for call.
func TestReadAndPromptRefuseWhatTheyCannotRun(t *testing.T) {
	f := newFakeServer(t)
	endpoint := f.srv.URL + "/mcp"
	dead := newFakeServer(t)
	dead.srv.Close()
	for _, args := range [][]string{
		{"read", endpoint},
		{"read", endpoint, "fake://doc/1", "--output", "xml"},
		{"read", endpoint, "fake://doc/1", "--auth", "bearer"},
		{"read", dead.srv.URL + "/mcp", "fake://doc/1", "--auth", "none"},
		{"read", endpoint, "fake://doc/1", "--", "npx"},
		{"prompt", endpoint},
		{"prompt", endpoint, "summarise", "--arg", "noequals"},
		{"prompt", endpoint, "summarise", "--output", "md"},
		{"prompt", endpoint, "summarise", "--auth", "none"},
	} {
		if out, code := run(t, append(args, "--log-level", "error")...); code != 1 || out != "" {
			t.Errorf("%v: exit %d, stdout %q", args, code, out)
		}
	}
}

// TestReadAndPromptSurfaceServerErrors: a JSON-RPC error is passmcp not
// getting what it asked for, exit 1, and the message says why.
func TestReadAndPromptSurfaceServerErrors(t *testing.T) {
	f := newFakeServer(t)
	f.open = true
	f.failReads = true
	for _, args := range [][]string{
		{"read", f.srv.URL + "/mcp", "fake://missing"},
		{"prompt", f.srv.URL + "/mcp", "missing"},
	} {
		if out, code := run(t, append(args, "--log-level", "error")...); code != 1 || out != "" {
			t.Errorf("%v: exit %d, stdout %q", args, code, out)
		}
	}
}

// TestOperandTargetNamesTheCommand: read and prompt take two operands the
// way call does, and their usage errors must name the right command.
func TestOperandTargetNamesTheCommand(t *testing.T) {
	parse := func(argv ...string) (engine.TargetSpec, string, error) {
		resetAll()
		var (
			target  engine.TargetSpec
			operand string
			err     error
		)
		c := &cobra.Command{Use: "read", Args: cobra.ArbitraryArgs,
			RunE: func(c *cobra.Command, args []string) error {
				target, operand, err = operandTarget(c, args, "read", "uri")
				return nil
			}}
		c.Flags().AddFlagSet(targetFlags())
		c.SetArgs(argv)
		c.SetOut(io.Discard)
		c.SetErr(io.Discard)
		if e := c.Execute(); e != nil {
			t.Fatalf("parse: %v", e)
		}
		return target, operand, err
	}
	target, uri, err := parse("--stdio", "file:///a", "--", "npx", "server")
	if err != nil || target.Command != "npx" || uri != "file:///a" {
		t.Errorf("stdio form: %+v %q %v", target, uri, err)
	}
	if _, _, err := parse("https://x/mcp"); err == nil || !strings.Contains(err.Error(), "passmcp read <endpoint> <uri>") {
		t.Errorf("usage error = %v", err)
	}
	if _, _, err := parse("--stdio", "--", "npx"); err == nil || !strings.Contains(err.Error(), "passmcp read --stdio <uri>") {
		t.Errorf("stdio usage error = %v", err)
	}
}

// TestReadAndPromptAreDocumented: help, manpages and completions are
// generated from the command tree, so being in it is being documented.
func TestReadAndPromptAreDocumented(t *testing.T) {
	// Every generated completion script asks the binary through
	// __complete, so what it answers is what every shell offers.
	comp, _ := run(t, "__complete", "")
	for _, name := range []string{"read", "prompt"} {
		c, _, err := rootCmd.Find([]string{name})
		if err != nil || c.Name() != name || c.Short == "" || c.Long == "" {
			t.Errorf("%s is not a documented command: %v", name, err)
		}
		if !strings.Contains(comp, "\n"+name+"\t") {
			t.Errorf("completion does not offer %s:\n%s", name, comp)
		}
	}
}

// TestWriteResourceDescribesBinaryContent rather than dumping it.
func TestWriteResourceDescribesBinaryContent(t *testing.T) {
	var b bytes.Buffer
	writeResource(&b, "file:///logo.png", 1500*time.Microsecond, &passmcp.ReadResourceResult{Contents: []passmcp.ResourceContents{
		{URI: "file:///logo.png", MimeType: "image/png", Blob: "AAAA"},
		{URI: "file:///notes.txt", Text: "plain"},
	}})
	out := b.String()
	for _, want := range []string{"file:///logo.png ok in 2ms", "[blob file:///logo.png, 3 bytes, image/png]", "plain"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

// assertNothingInvoked: resources/read and prompts/get are non-mutating
// by the specification, and neither may reach a tool (ADR-0004).
func assertNothingInvoked(t *testing.T, f *fakeServer) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) != 0 {
		t.Errorf("a read-only command invoked tools: %v", f.calls)
	}
}

// assertNoIssuedSecret: neither the client secret nor a token the fake
// authorization server issued may appear in the output.
func assertNoIssuedSecret(t *testing.T, f *fakeServer, out string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.Contains(out, "client_secret=sec") || strings.Contains(out, `"sec"`) {
		t.Error("the client secret reached the output")
	}
	for tok := range f.tokens {
		if strings.Contains(out, tok) {
			t.Errorf("issued token %s reached the output", tok)
		}
	}
}
