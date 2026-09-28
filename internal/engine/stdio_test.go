// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// A target is a URL or a program, and the spec is where that choice has to
// be expressible — otherwise only the surface that invented it can make it.
// These cover the spec half; the run itself is exercised in internal/probe.

func stdioSpec() RunSpec {
	return RunSpec{Target: TargetSpec{
		Command: "npx", Args: []string{"-y", "server-everything", "stdio"},
	}}.WithDefaults()
}

func TestStdioTargetValidates(t *testing.T) {
	if err := stdioSpec().Validate(); err != nil {
		t.Fatalf("a command with no endpoint should be valid: %v", err)
	}

	// Both is not "one of each". A run that silently preferred one would
	// report on a server nobody named.
	both := stdioSpec()
	both.Target.Endpoint = "https://x/mcp"
	err := both.Validate()
	if err == nil {
		t.Fatal("a spec with both a URL and a command was accepted")
	}
	if !strings.Contains(err.Error(), "one target") {
		t.Errorf("the error does not say what is wrong: %v", err)
	}
}

// TestStdioRefusesCredentials is the one that matters.
//
// There is no origin to authorize against over a pipe, so a token has
// nowhere to go. Dropping it quietly would produce a report that reads as a
// test of an authenticated server and is not one, so it is an error — and
// the error has to say what to do instead.
func TestStdioRefusesCredentials(t *testing.T) {
	s := stdioSpec()
	s.Creds = CredSpec{Mode: "bearer", Token: "t"}
	err := s.Validate()
	if err == nil {
		t.Fatal("credentials were accepted for a stdio target")
	}
	for _, want := range []string{"no meaning over stdio", "--stdio-env"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should mention %q: %v", want, err)
		}
	}

	// And the same spec over HTTP is fine, so this is about the transport
	// rather than about the credential.
	h := s
	h.Target = TargetSpec{Endpoint: "https://x/mcp"}
	if err := h.Validate(); err != nil {
		t.Errorf("the same credentials over HTTP: %v", err)
	}
}

func TestTargetDescribe(t *testing.T) {
	if got := stdioSpec().Target.Describe(); got != "npx -y server-everything stdio" {
		t.Errorf("Describe() = %q", got)
	}
	http := TargetSpec{Endpoint: "https://x/mcp"}
	if got := http.Describe(); got != "https://x/mcp" {
		t.Errorf("Describe() = %q", got)
	}
	if http.Stdio() {
		t.Error("a URL target reports itself as stdio")
	}
	// Whitespace is not a command. Otherwise `--stdio -- " "` would be
	// treated as a target and fail much later, in exec.
	if (TargetSpec{Command: "  "}).Stdio() {
		t.Error("a blank command counts as a target")
	}
	if got := stdioSpec().String(); !strings.Contains(got, "npx -y server-everything") {
		t.Errorf("String() does not name the target: %q", got)
	}
}

// TestStdioReachesProbeOptions: the spec is only a peer surface's route to a
// capability if it actually carries it down.
func TestStdioReachesProbeOptions(t *testing.T) {
	s := stdioSpec()
	s.Target.Dir = "/tmp"
	s.Target.PassEnv = []string{"GITHUB_TOKEN"}
	s.Target.Env = []string{"ONLY=this"}

	cr, err := s.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	opts := s.probeOptions(cr, nil, nil)

	if opts.Stdio == nil {
		t.Fatal("probeOptions dropped the command; no run would speak stdio")
	}
	if opts.Stdio.Command != "npx" || !slices.Equal(opts.Stdio.Args, []string{"-y", "server-everything", "stdio"}) {
		t.Errorf("command = %q %v", opts.Stdio.Command, opts.Stdio.Args)
	}
	if opts.Stdio.Dir != "/tmp" || !slices.Equal(opts.Stdio.PassEnv, []string{"GITHUB_TOKEN"}) ||
		!slices.Equal(opts.Stdio.Env, []string{"ONLY=this"}) {
		t.Errorf("environment not carried: %+v", opts.Stdio)
	}
	if opts.Endpoint != "" {
		t.Errorf("Endpoint = %q; a stdio run has no endpoint and probe.Run refuses both", opts.Endpoint)
	}
	if opts.HTTPClient != nil {
		t.Error("a stdio run carries an http.Client, which nothing will use")
	}

	// An HTTP spec keeps both, so the branch above is a branch.
	h := RunSpec{Target: TargetSpec{Endpoint: "https://x/mcp"}}.WithDefaults()
	hopts := h.probeOptions(cr, nil, nil)
	if hopts.Stdio != nil || hopts.Endpoint == "" || hopts.HTTPClient == nil {
		t.Errorf("HTTP options were reshaped: stdio=%v endpoint=%q client=%v",
			hopts.Stdio != nil, hopts.Endpoint, hopts.HTTPClient != nil)
	}
}

// TestStdioSpecCarriesNoValuesAcrossJSON: the command and the forwarded
// names travel, the values do not. A spec that crosses a process or a
// network boundary carries references to secrets, never secrets.
func TestStdioSpecCarriesNoValuesAcrossJSON(t *testing.T) {
	s := stdioSpec()
	s.Target.PassEnv = []string{"GITHUB_TOKEN"}
	s.Target.Env = []string{"GITHUB_TOKEN=ghp_the_actual_secret"}

	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "ghp_the_actual_secret") {
		t.Error("a variable's value reached the serialised spec")
	}
	if !strings.Contains(string(b), "GITHUB_TOKEN") {
		t.Error("the forwarded name was dropped; a receiver could not reproduce the run")
	}

	var back RunSpec
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Target.Command != "npx" || !slices.Equal(back.Target.Args, s.Target.Args) {
		t.Errorf("the command did not round-trip: %+v", back.Target)
	}
	if back.Target.Env != nil {
		t.Errorf("Env crossed JSON: %v", back.Target.Env)
	}
}
