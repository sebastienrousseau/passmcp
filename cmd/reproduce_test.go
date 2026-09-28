// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"satellion.com/passmcp-reporting/attestation"
	"satellion.com/passmcp/internal/attest"
	"satellion.com/passmcp/internal/engine"
)

// A repeat of an unchanged server against an unchanged plan finds nothing
// worse; a statement that claimed more than the server does is caught.
func TestVerifyReproducesTheRecordedRun(t *testing.T) {
	endpoint, _, statement := attestFixture(t)
	st, err := attest.Parse([]byte(statement))
	if err != nil {
		t.Fatal(err)
	}
	if st.Predicate.Plan == nil || st.Predicate.Plan.Credentials != "none" {
		t.Fatalf("the statement records no usable plan: %+v", st.Predicate.Plan)
	}
	path := writeTemp(t, "statement.json", statement)

	t.Run("unchanged", func(t *testing.T) {
		out, code := run(t, "verify", path, "--reproduce", "--endpoint", endpoint)
		if code != 0 || !strings.Contains(out, "no check got worse") || !strings.Contains(out, "repeated by passmcp") {
			t.Fatalf("exit %d:\n%s", code, out)
		}
	})

	t.Run("claimed more than it does", func(t *testing.T) {
		doctored, _ := attest.Parse([]byte(statement))
		var claimed string
		for i, v := range doctored.Predicate.Verdicts {
			if v.Status == "warn" || v.Status == "fail" {
				claimed = v.ID
				doctored.Predicate.Verdicts[i].Status, doctored.Predicate.Verdicts[i].Severity = "pass", ""
				c := &doctored.Predicate.Counts
				if v.Status == "warn" {
					c.Warn--
				} else {
					c.Fail--
				}
				c.Pass++
				break
			}
		}
		if claimed == "" {
			t.Fatal("the fixture run found nothing to warn or fail on, so nothing can be claimed")
		}
		b, _ := doctored.Marshal()
		out, code := run(t, "verify", writeTemp(t, "doctored.json", string(b)), "--reproduce", "--endpoint", endpoint, "--output", "json")
		if code != 2 {
			t.Fatalf("a regression passed the gate (exit %d):\n%s", code, out)
		}
		var v struct {
			Reproduced struct {
				Regressed []struct{ ID string } `json:"regressed"`
			} `json:"reproduced"`
		}
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, out)
		}
		found := false
		for _, r := range v.Reproduced.Regressed {
			found = found || r.ID == claimed
		}
		if !found {
			t.Errorf("%s is not among the regressions: %+v", claimed, v.Reproduced)
		}
	})
}

// Each thing the operator must supply, and each way a statement could try
// to choose it instead, is refused before anything is contacted.
func TestReproduceRefusesWhatTheOperatorDidNotGrant(t *testing.T) {
	target := attestation.Target{Transport: "http", Endpoint: "https://mcp.example.com/mcp"}
	statement := func(mutate func(*engine.RunSpec, *attestation.Plan)) *attest.Statement {
		spec := engine.RunSpec{Target: engine.TargetSpec{Endpoint: target.Endpoint}}
		p := &attestation.Plan{Credentials: "none", OS: "linux", Arch: "amd64"}
		if mutate != nil {
			mutate(&spec, p)
		}
		raw, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		p.Spec = raw
		return &attest.Statement{
			Subject:   []attest.Subject{attestation.SubjectFor(target)},
			Predicate: attest.Evaluation{Target: target, Plan: p},
		}
	}
	cases := []struct {
		name     string
		st       *attest.Statement
		endpoint string
		setup    func()
		want     string
	}{
		{"no endpoint named", statement(nil), "", nil, "name it with --endpoint"},
		{"endpoint the statement does not cover", statement(nil), "https://other.example.com/mcp", nil, "does not cover"},
		{"no plan", func() *attest.Statement { s := statement(nil); s.Predicate.Plan = nil; return s }(), target.Endpoint, nil, "records no plan"},
		{"plan not a spec", func() *attest.Statement {
			s := statement(nil)
			s.Predicate.Plan.Spec = json.RawMessage(`[1]`)
			return s
		}(), target.Endpoint, nil, "not a passmcp run spec"},
		{"plan about another target", statement(func(s *engine.RunSpec, _ *attestation.Plan) {
			s.Target.Endpoint = "https://attacker.example/mcp"
		}), target.Endpoint, nil, "about a different target"},
		{"plan runs a program", statement(func(s *engine.RunSpec, _ *attestation.Plan) {
			s.Target = engine.TargetSpec{Command: "sh", Args: []string{"-c", "true"}}
		}), target.Endpoint, nil, "about a different target"},
		{"permission not granted", statement(func(s *engine.RunSpec, _ *attestation.Plan) {
			s.Policy.AllowMutations = true
		}), target.Endpoint, nil, "had --allow-mutations"},
		{"fault not granted", statement(func(s *engine.RunSpec, _ *attestation.Plan) {
			s.Egress.FaultUpstream = true
		}), target.Endpoint, nil, "had --fault-upstream"},
		{"permission not recorded", statement(nil), target.Endpoint, func() { reproPerm.AllowPrivateHosts = true },
			"did not have --insecure-allow-private-hosts"},
		{"credentials not supplied", statement(func(_ *engine.RunSpec, p *attestation.Plan) {
			p.Credentials, p.ByValue = "bearer", []string{"token"}
		}), target.Endpoint, nil, "authenticated as bearer and this one would be none; supply credentials with the flags passmcp check takes (it was given token)"},
		{"header not supplied", statement(func(_ *engine.RunSpec, p *attestation.Plan) {
			p.ByValue = []string{"header X-API-Key", "param tenant"}
		}), target.Endpoint, nil, `--header "X-API-Key: …", --param tenant=…`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetAll()
			t.Setenv("PASSMCP_TOKEN", "")
			verifyEndpoint = tc.endpoint
			if tc.setup != nil {
				tc.setup()
			}
			_, err := reproduceSpec(tc.st)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to say %q", err, tc.want)
			}
		})
	}
}

// The environment-variable name a statement recorded is not read, and a
// run that sent nothing sends nothing again, whatever the environment holds.
func TestReproduceTakesCredentialsOnlyFromTheOperator(t *testing.T) {
	resetAll()
	target := attestation.Target{Transport: "http", Endpoint: "https://mcp.example.com/mcp"}
	t.Setenv("VICTIM_SECRET", "not-for-this-server")
	t.Setenv("PASSMCP_TOKEN", "ambient")

	spec := engine.RunSpec{Target: engine.TargetSpec{Endpoint: target.Endpoint},
		Creds: engine.CredSpec{Mode: "bearer", TokenEnv: "VICTIM_SECRET"}}
	raw, _ := json.Marshal(spec)
	st := &attest.Statement{
		Subject: []attest.Subject{attestation.SubjectFor(target)},
		Predicate: attest.Evaluation{Target: target, Plan: &attestation.Plan{
			Spec: raw, Credentials: "bearer"}},
	}
	verifyEndpoint = target.Endpoint
	tokenEnv = "MY_TOKEN"
	t.Setenv("MY_TOKEN", "mine")
	got, err := reproduceSpec(st)
	if err != nil {
		t.Fatal(err)
	}
	if got.Creds.TokenEnv != "MY_TOKEN" {
		t.Errorf("token read from %q; only the operator names where a secret comes from", got.Creds.TokenEnv)
	}
	if got.Output.Format != engine.FormatAttestation || got.Version != Version {
		t.Errorf("output %+v, version %q", got.Output, got.Version)
	}

	resetAll()
	verifyEndpoint = target.Endpoint
	st.Predicate.Plan.Credentials = "none"
	got, err = reproduceSpec(st)
	if err != nil {
		t.Fatal(err)
	}
	if got.Creds.Mode != "none" || got.Creds.TokenEnv != "" {
		t.Errorf("a run that sent nothing would now send %+v", got.Creds)
	}
}

func TestHostOfNamesTheMachine(t *testing.T) {
	if got := hostOf(nil); got != "an unrecorded host" {
		t.Errorf("nil: %q", got)
	}
	if got := hostOf(&attestation.Plan{OS: "linux", Arch: "arm64", Kernel: "6.8.0"}); got != "linux/arm64 6.8.0" {
		t.Errorf("got %q", got)
	}
	if got := hostOf(&attestation.Plan{OS: "windows", Arch: "amd64"}); got != "windows/amd64" {
		t.Errorf("got %q", got)
	}
}
