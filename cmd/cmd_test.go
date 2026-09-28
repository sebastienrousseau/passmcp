// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/engine"
)

func resetFlags() {
	authMode, token, tokenEnv, basic, clientID, clientSecret, clientSecretEnv = "auto", "", "", "", "", "", ""
	headers, params, toolArgs = nil, nil, nil
	clientMetadataURL, scope, tokenURL, authURL, resource = "", "", "", "", ""
	endpointFromProfile, configPath, profileName = "", "", ""
	useStdio, stdioDir = false, ""
	stdioEnv, stdioOnly = nil, nil
}

func TestParseToolArgs(t *testing.T) {
	got, err := parseToolArgs([]string{"search.q=hello", "search.limit=5", "other.flag=true", `x.obj={"a":1}`})
	if err != nil {
		t.Fatal(err)
	}
	if got["search"]["q"] != "hello" || got["search"]["limit"] != float64(5) || got["other"]["flag"] != true {
		t.Errorf("got %v", got)
	}
	if m, ok := got["x"]["obj"].(map[string]any); !ok || m["a"] != float64(1) {
		t.Errorf("json object not parsed: %v", got["x"])
	}
	for _, bad := range []string{"noequals", "nodot=1", ".field=1", "tool.=1"} {
		if _, err := parseToolArgs([]string{bad}); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

func TestBuildCredsPrecedenceAndValidation(t *testing.T) {
	resetFlags()
	t.Setenv(creds.EnvToken, "from-env")
	c, err := buildCreds()
	if err != nil || c.Effective() != creds.ModeBearer || c.Token != "from-env" {
		t.Fatalf("env token: %v %+v", err, c)
	}
	token = "from-flag"
	c, _ = buildCreds()
	if c.Token != "from-flag" || c.Sources["token"] != "flag --token" {
		t.Errorf("flag must win: %+v", c)
	}
	resetFlags()
	os.Unsetenv(creds.EnvToken)
	t.Setenv("MY_TOK", "env-named")
	tokenEnv = "MY_TOK"
	headers = []string{"X-Api-Key: k1", "X-Tenant=acme"}
	params = []string{"profile_id=t1"}
	c, err = buildCreds()
	if err != nil || c.Token != "env-named" || c.Headers["X-Api-Key"] != "k1" || c.Headers["X-Tenant"] != "acme" || c.Params.Get("profile_id") != "t1" {
		t.Errorf("%v %+v", err, c)
	}
	resetFlags()
	authMode = "bearer"
	if _, err := buildCreds(); err == nil {
		t.Error("bearer without token must fail")
	}
	resetFlags()
	headers = []string{"garbage"}
	if _, err := buildCreds(); err == nil {
		t.Error("bad header must fail")
	}
}

func TestConfigProfileSuppliesEndpointAndSettings(t *testing.T) {
	resetAll()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(`{"defaults":{"rps":7},"profiles":{"acme":{"endpoint":"https://acme/mcp","settings":{"auth":"client-credentials","client-id":"cid","param":["profile_id=t1"]}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath, profileName = p, "acme"
	// Simulate cobra having parsed no explicit flags on checkCmd.
	if err := applyConfig(checkCmd); err != nil {
		t.Fatal(err)
	}
	ep, err := resolveEndpoint(nil)
	if err != nil || ep != "https://acme/mcp" {
		t.Errorf("endpoint = %q %v", ep, err)
	}
	if rps != 7 || authMode != "client-credentials" || clientID != "cid" || len(params) != 1 {
		t.Errorf("settings not applied: rps=%v auth=%s id=%s params=%v", rps, authMode, clientID, params)
	}
	if ep, _ := resolveEndpoint([]string{"https://explicit/mcp"}); ep != "https://explicit/mcp" {
		t.Error("positional endpoint must win")
	}
	profileName = "missing"
	if err := applyConfig(checkCmd); err == nil || !strings.Contains(err.Error(), `profile "missing"`) {
		t.Errorf("missing profile: %v", err)
	}
	resetFlags()
	rps = 2
}

func TestKnownFlagNamesCoversEveryCommand(t *testing.T) {
	known := knownFlagNames()
	for _, f := range []string{"auth", "token-env", "rps", "report-dir", "log-level", "json", "arg", "phases"} {
		if !known[f] {
			t.Errorf("flag %s not known", f)
		}
	}
}

func TestVersionCommand(t *testing.T) {
	resetAll()
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"version"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	_ = json.Valid // keep import
}

// TestResolveTarget covers the operand grammar, which is the part of this
// feature a user meets first and the part most likely to be got wrong.
//
// Cobra's ArgsLenAtDash is what separates passmcp's arguments from the
// server's, and it is only correct if the flag set has actually parsed the
// line — so these drive a real command rather than calling the resolver with
// a hand-built slice.
func TestResolveTarget(t *testing.T) {
	cases := []struct {
		name    string
		argv    []string
		want    engine.TargetSpec
		wantErr string
	}{
		{
			name: "a URL is the positional",
			argv: []string{"https://mcp.example.com/mcp"},
			want: engine.TargetSpec{Endpoint: "https://mcp.example.com/mcp"},
		},
		{
			name: "a command after --",
			argv: []string{"--stdio", "--", "npx", "-y", "server", "--its-own-flag"},
			want: engine.TargetSpec{Command: "npx", Args: []string{"-y", "server", "--its-own-flag"}},
		},
		{
			name:    "both a URL and a command is one target too many",
			argv:    []string{"--stdio", "https://mcp.example.com/mcp", "--", "npx", "server"},
			wantErr: "one target",
		},
		{
			name:    "--stdio with nothing to run",
			argv:    []string{"--stdio"},
			wantErr: "needs the command to run",
		},
		{
			name:    "a command without --stdio",
			argv:    []string{"--", "npx", "server"},
			wantErr: "pass --stdio",
		},
		{
			name: "forwarded variables are named, not inherited",
			argv: []string{"--stdio", "--stdio-env", "GITHUB_TOKEN", "--stdio-dir", "/tmp", "--", "server"},
			want: engine.TargetSpec{Command: "server", Args: []string{}, Dir: "/tmp", PassEnv: []string{"GITHUB_TOKEN"}},
		},
		{
			name:    "--stdio-set without a value",
			argv:    []string{"--stdio", "--stdio-set", "GITHUB_TOKEN", "--", "server"},
			wantErr: "has no value",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetAll()
			var got engine.TargetSpec
			var gotErr error
			cmd := &cobra.Command{
				Use:  "probe",
				Args: cobra.ArbitraryArgs,
				RunE: func(c *cobra.Command, args []string) error {
					got, gotErr = resolveTarget(c, args)
					return nil
				},
			}
			cmd.Flags().AddFlagSet(targetFlags())
			cmd.SetArgs(tc.argv)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			if err := cmd.Execute(); err != nil {
				t.Fatalf("parse: %v", err)
			}

			if tc.wantErr != "" {
				if gotErr == nil {
					t.Fatalf("no error; got target %+v", got)
				}
				if !strings.Contains(gotErr.Error(), tc.wantErr) {
					t.Errorf("error %q does not mention %q", gotErr, tc.wantErr)
				}
				return
			}
			if gotErr != nil {
				t.Fatalf("resolveTarget: %v", gotErr)
			}
			if got.Endpoint != tc.want.Endpoint || got.Command != tc.want.Command ||
				got.Dir != tc.want.Dir ||
				!slices.Equal(got.Args, tc.want.Args) || !slices.Equal(got.PassEnv, tc.want.PassEnv) {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestCallTargetSplitsToolFromCommand: `call` has two operands and they swap
// places between transports, which is exactly the sort of grammar that ships
// broken.
func TestCallTargetSplitsToolFromCommand(t *testing.T) {
	run := func(argv ...string) (engine.TargetSpec, string, error) {
		resetAll()
		var target engine.TargetSpec
		var tool string
		var err error
		cmd := &cobra.Command{Use: "call", Args: cobra.ArbitraryArgs,
			RunE: func(c *cobra.Command, args []string) error {
				target, tool, err = callTarget(c, args)
				return nil
			}}
		cmd.Flags().AddFlagSet(targetFlags())
		cmd.SetArgs(argv)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		if e := cmd.Execute(); e != nil {
			t.Fatalf("parse: %v", e)
		}
		return target, tool, err
	}

	target, tool, err := run("https://mcp.example.com/mcp", "search")
	if err != nil || target.Endpoint != "https://mcp.example.com/mcp" || tool != "search" {
		t.Errorf("HTTP form: %+v %q %v", target, tool, err)
	}

	target, tool, err = run("--stdio", "get-sum", "--", "npx", "-y", "server")
	if err != nil || target.Command != "npx" || tool != "get-sum" {
		t.Errorf("stdio form: %+v %q %v", target, tool, err)
	}

	if _, _, err = run("--stdio", "--", "npx", "server"); err == nil {
		t.Error("a stdio call with no tool named was accepted")
	}
	if _, _, err = run("https://mcp.example.com/mcp"); err == nil {
		t.Error("a call with no tool named was accepted")
	}
}
