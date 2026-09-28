// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package fleet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp/internal/engine"
)

func TestParseAcceptsAWellFormedFleet(t *testing.T) {
	f, err := Parse([]byte(`
version: 1
state: runs
pacing:
  rps: 1.5
  samples: 2
  concurrency: 3
  call_timeout: 20s
servers:
  - name: docs
    endpoint: https://docs.example/mcp
    credential:
      token_env: DOCS_TOKEN
    policy: policies/docs.json
  - name: local
    command: ["npx", "-y", "@acme/mcp@1.2.3"]
    transport: stdio
  - name: billing
    endpoint: https://billing.example/mcp
    credential:
      mode: client-credentials
      client_id: passmcp
      client_secret_env: BILLING_SECRET
      token_url: https://auth.example/token
      scope: mcp.read
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Servers) != 3 || f.State != "runs" || *f.Pacing.RPS != 1.5 {
		t.Fatalf("parsed %+v", f)
	}
	if f.Servers[1].transport() != "stdio" || f.Servers[0].Credential.mode() != "bearer" {
		t.Error("transport and credential mode defaults")
	}
}

// A fleet file is committed and mounted into containers; a secret written
// into it must be refused, never quietly ignored.
func TestParseRefusesInlineSecretsAndMistakes(t *testing.T) {
	cases := map[string]string{
		"inline token":        "version: 1\nservers:\n  - name: a\n    endpoint: https://x/mcp\n    credential:\n      token: abc123\n",
		"unknown key":         "version: 1\nservers:\n  - name: a\n    endpoint_url: https://x/mcp\n",
		"wrong version":       "version: 2\nservers:\n  - name: a\n    endpoint: https://x/mcp\n",
		"no servers":          "version: 1\n",
		"both targets":        "version: 1\nservers:\n  - name: a\n    endpoint: https://x/mcp\n    command: [x]\n",
		"no target":           "version: 1\nservers:\n  - name: a\n",
		"transport mismatch":  "version: 1\nservers:\n  - name: a\n    endpoint: https://x/mcp\n    transport: stdio\n",
		"duplicate name":      "version: 1\nservers:\n  - name: a\n    endpoint: https://x/mcp\n  - name: a\n    endpoint: https://y/mcp\n",
		"unsafe name":         "version: 1\nservers:\n  - name: ../etc\n    endpoint: https://x/mcp\n",
		"bearer without env":  "version: 1\nservers:\n  - name: a\n    endpoint: https://x/mcp\n    credential:\n      mode: bearer\n",
		"client creds partly": "version: 1\nservers:\n  - name: a\n    endpoint: https://x/mcp\n    credential:\n      mode: client-credentials\n      client_id: c\n",
		"unknown mode":        "version: 1\nservers:\n  - name: a\n    endpoint: https://x/mcp\n    credential:\n      mode: magic\n",
		"bad timeout":         "version: 1\npacing:\n  call_timeout: soon\nservers:\n  - name: a\n    endpoint: https://x/mcp\n",
		"not yaml":            "version: [\n",
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse([]byte("version: 1\nservers:\n  - name: a\n    endpoint: https://x/mcp\n    credential:\n      mode: none\n")); err != nil {
		t.Errorf("mode none needs nothing else: %v", err)
	}
}

func TestLoadNamesTheFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fleet.yaml")
	if err := os.WriteFile(p, []byte("version: 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "fleet.yaml") {
		t.Errorf("the error names the file: %v", err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("a missing file is an error")
	}
}

func TestSpecForCarriesTargetCredentialsPolicyAndPacing(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.json"), []byte(`{"version":1,"name":"strict","max_fail":0}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rps := 3.0
	f := &File{Version: 1, Pacing: Pacing{RPS: &rps, CallTimeout: "5s"}}
	r := Runner{Version: "v", BaseDir: dir}
	spec, err := r.specFor(f, Server{Name: "s", Command: []string{"node", "server.js"}, Policy: "p.json",
		Credential: &Credential{Mode: "client-credentials", ClientID: "c", ClientSecretEnv: "S", TokenURL: "https://t", Scope: "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Target.Command != "node" || len(spec.Target.Args) != 1 || spec.Gate == nil || spec.Pacing.RPS != 3 ||
		spec.Pacing.CallTimeout != 5*time.Second || spec.Creds.ClientSecretEnv != "S" || spec.Creds.Mode != "client-credentials" {
		t.Fatalf("spec = %+v", spec)
	}
	if _, err := r.specFor(f, Server{Name: "s", Endpoint: "https://x/mcp", Policy: "missing.json"}); err == nil {
		t.Error("a missing policy is an error")
	}
	if c := credSpecFor(nil); c.Mode != "none" {
		t.Errorf("no credential is mode none: %+v", c)
	}
	abs := filepath.Join(t.TempDir(), "p.json") // absolute on every platform
	if got := (Runner{BaseDir: t.TempDir()}).resolve(abs); got != abs {
		t.Errorf("an absolute path stays absolute: %s", got)
	}
}

// A server whose spec cannot be built is unreachable, with the reason.
func TestABadPolicyMakesTheServerUnreachable(t *testing.T) {
	r := runner(t, clock())
	sum, err := r.Run(context.Background(), fleetOf(Server{Name: "a", Endpoint: "https://x/mcp", Policy: "nope.json"}))
	if err != nil {
		t.Fatal(err)
	}
	if s := sum.Servers[0]; s.Status != StatusUnreachable || !strings.Contains(s.Error, "nope.json") {
		t.Fatalf("got %+v", s)
	}
}

// A check that returns no report and no error is still not a pass.
func TestARunWithNoReportIsUnreachable(t *testing.T) {
	r := runner(t, clock())
	r.Check = func(context.Context, engine.RunSpec) *engine.Result { return &engine.Result{} }
	sum, err := r.Run(context.Background(), fleetOf(Server{Name: "a", Endpoint: "https://x/mcp"}))
	if err != nil {
		t.Fatal(err)
	}
	if s := sum.Servers[0]; s.Status != StatusUnreachable || s.Error == "" {
		t.Fatalf("got %+v", s)
	}
}

func TestExitAndWorst(t *testing.T) {
	if exitOf([]ServerResult{{Exit: ExitOK}, {Exit: ExitError}}) != ExitError {
		t.Error("unreachable outranks clean")
	}
	if exitOf([]ServerResult{{Exit: ExitError}, {Exit: ExitFailed}}) != ExitFailed {
		t.Error("failed outranks unreachable")
	}
	if w, c := worstOf(nil); w != "" || c {
		t.Error("no changes, no worst")
	}
	if w, c := worstOf([]Change{{Severity: "notable"}, {Severity: "critical"}}); w != "critical" || !c {
		t.Error("worst is critical")
	}
}

func TestSummaryDriftCarriesBothDigests(t *testing.T) {
	sum := &Summary{Started: time.Now(), Servers: []ServerResult{{
		Name: "a", Endpoint: "https://x/mcp", Previous: "sha256:1", Attestation: "sha256:2",
		Changes: []Change{{Kind: KindVerdictRegessed, Check: "net.tls", Severity: "serious", Before: "pass", After: "fail"}},
	}}}
	d := sum.Drift()
	if len(d) != 1 || d[0].Tool != "net.tls" || d[0].BeforeAttestation != "sha256:1" || d[0].AfterAttestation != "sha256:2" {
		t.Fatalf("drift = %+v", d)
	}
}

func TestCorruptStateIsAnErrorNotAPass(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, latestFileName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLatest(dir); err == nil {
		t.Error("a corrupt pointer is an error")
	}
	if l, err := loadLatest(t.TempDir()); l != nil || err != nil {
		t.Error("a server never run has no pointer and no error")
	}
	if _, err := compareRuns(&latest{Dir: filepath.Join(dir, "gone")}, dir, nil); err == nil {
		t.Error("a missing previous run is an error")
	}
	if _, err := fileDigest(filepath.Join(dir, "absent")); err == nil {
		t.Error("digest of a missing file is an error")
	}
	if err := writeJSON(filepath.Join(dir, latestFileName, "x"), 1); err == nil {
		t.Error("writing under a file is an error")
	}
	if _, err := (Runner{StateDir: filepath.Join(dir, latestFileName)}).Run(context.Background(), fleetOf()); err == nil {
		t.Error("a state directory that is a file is an error")
	}
}

// Two runs in the same second must not share a directory, or the second
// would overwrite the run it is compared against.
func TestARunInTheSameSecondGetsItsOwnDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "20260101T000000Z")
	if got := freshRunDir(dir); got != dir {
		t.Fatalf("an unused directory is kept: %s", got)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir+"-2", 0o700); err != nil {
		t.Fatal(err)
	}
	if got := freshRunDir(dir); got != dir+"-3" {
		t.Errorf("want the next free suffix, got %s", got)
	}
}
