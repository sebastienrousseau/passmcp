// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// policyFixture writes a policy file and returns its path.
func policyFixture(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// farFuture keeps an exemption alive without pinning the test to a date that
// will quietly start failing. A fixed date would make this test a time bomb,
// which is the opposite of what an expiry test should be.
func farFuture() string { return time.Now().AddDate(5, 0, 0).Format("2006-01-02") }

// The default rule is "any failing finding fails the run". A policy replaces
// it, which is the whole point of an exemption: a team that has decided in
// writing that one failure is acceptable has to get a pass, or the exemption
// changes nothing and the gate gets turned off instead.
func TestCheckPolicyReplacesTheDefaultFailureRule(t *testing.T) {
	f := newFakeServer(t)
	endpoint := f.srv.URL + "/mcp"
	args := func(extra ...string) []string {
		base := []string{"check", endpoint, "--auth", "client-credentials",
			"--client-id", "cid", "--client-secret", "sec", "--param", "profile_id=t1"}
		return append(append(base, extra...), fastFlags()...)
	}

	// Without a policy this run exits 2: the fake's search tool violates its
	// own outputSchema.
	out, code := run(t, args()...)
	if code != 2 {
		t.Fatalf("the fixture is supposed to fail without a policy (exit %d):\n%s", code, out)
	}

	// With a policy that states no rule about that failure, it passes — and
	// has to say so rather than looking like a clean run.
	pol := policyFixture(t, `{"version":1,"name":"minimal","must_pass":["net.dns"]}`)
	out, code = run(t, args("--policy", pol)...)
	if code != 0 {
		t.Fatalf("the policy was met but the run exited %d:\n%s", code, out)
	}
	for _, want := range []string{"policy     minimal", "net.dns passed", "the policy is met"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	}
}

// A policy that is not met has to fail the run even when nothing else did.
func TestCheckPolicyCanFailAPassingRun(t *testing.T) {
	f := newFakeServer(t)
	f.open = true
	endpoint := f.srv.URL + "/mcp"
	pol := policyFixture(t, `{"version":1,"name":"strict","min_score":100}`)

	out, code := run(t, append([]string{
		"check", endpoint, "--policy", pol, "--phases", "net,discovery,auth,handshake",
	}, fastFlags()...)...)
	if code != 2 {
		t.Fatalf("an unmet policy did not fail the run (exit %d):\n%s", code, out)
	}
	if !strings.Contains(out, "the policy is not met") {
		t.Errorf("output does not say the policy failed:\n%s", out)
	}
}

// An exemption is the feature that makes a gate adoptable, so the end-to-end
// path has to work: a real failing check, excused in writing, with a date.
func TestCheckPolicyExemptionExcusesARealFailure(t *testing.T) {
	f := newFakeServer(t)
	endpoint := f.srv.URL + "/mcp"
	// The protected fake, all phases: its search tool violates its own
	// outputSchema, which is a genuine failure rather than one this test
	// arranged.
	args := func(extra ...string) []string {
		base := []string{"check", endpoint, "--auth", "client-credentials",
			"--client-id", "cid", "--client-secret", "sec", "--param", "profile_id=t1"}
		return append(append(base, extra...), fastFlags()...)
	}

	// Establish what actually fails, rather than assuming. A hard-coded check
	// id here would make the test pass for the wrong reason the moment the
	// fixture changed.
	dir := t.TempDir()
	out, code := run(t, args("--report-dir", dir)...)
	failing := failingChecks(t, filepath.Join(dir, "report.json"))
	if len(failing) == 0 {
		t.Fatalf("the fixture produced no failure to exempt (exit %d):\n%s", code, out)
	}

	var ex []string
	for _, id := range failing {
		ex = append(ex, `{"check":"`+id+`","reason":"accepted for this fixture","expires":"`+farFuture()+`","ticket":"SEC-1"}`)
	}
	pol := policyFixture(t, `{"version":1,"name":"with exceptions","max_fail":0,"exemptions":[`+strings.Join(ex, ",")+`]}`)

	out, code = run(t, args("--policy", pol)...)
	if code != 0 {
		t.Fatalf("the exemptions did not excuse the failures (exit %d):\n%s", code, out)
	}
	// The pass must never be silent about how it was reached.
	if !strings.Contains(out, "exempted") {
		t.Errorf("the output does not say a failure was excused:\n%s", out)
	}
	if !strings.Contains(out, "SEC-1") {
		t.Errorf("the output does not say where the decision is recorded:\n%s", out)
	}
}

// An expired exemption fails, and the message has to be about the decision
// rather than about the server: the reader's next action is to renew it.
func TestCheckPolicyExpiredExemption(t *testing.T) {
	f := newFakeServer(t)
	f.open = true
	endpoint := f.srv.URL + "/mcp"
	pol := policyFixture(t, `{"version":1,"name":"stale","exemptions":[
	  {"check":"net.dns","reason":"was flaky","expires":"2020-01-01"}]}`)

	out, code := run(t, append([]string{
		"check", endpoint, "--policy", pol, "--phases", "net",
	}, fastFlags()...)...)
	if code != 2 {
		t.Fatalf("an expired exemption did not fail the run (exit %d):\n%s", code, out)
	}
	if !strings.Contains(out, "expired 2020-01-01") {
		t.Errorf("the output does not name the expiry:\n%s", out)
	}
}

// A malformed or future-versioned policy must stop the run before it starts,
// with exit 1 rather than 2: nothing was measured, so there is no verdict
// about the server to report.
func TestCheckPolicyRefusals(t *testing.T) {
	f := newFakeServer(t)
	endpoint := f.srv.URL + "/mcp"
	cases := map[string]struct{ body, mentions string }{
		"a misspelled rule":         {`{"version":1,"name":"p","must_pas":["a"]}`, "must_pas"},
		"a later version":           {`{"version":99,"name":"p"}`, "upgrade passmcp"},
		"an exemption with no date": {`{"version":1,"name":"p","exemptions":[{"check":"a","reason":"r"}]}`, "permanent hole"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			pol := policyFixture(t, tc.body)
			_, stderr, code := runCapturingStderr(t, append([]string{
				"check", endpoint, "--policy", pol, "--phases", "net",
			}, fastFlags()...)...)
			if code == 0 {
				t.Fatal("the run proceeded with a policy it could not enforce")
			}
			if code == 2 {
				t.Errorf("exit 2 says the server failed; nothing was measured, so it should be 1")
			}
			_ = stderr
		})
	}

	t.Run("a missing file", func(t *testing.T) {
		_, _, code := runCapturingStderr(t, append([]string{
			"check", endpoint, "--policy", filepath.Join(t.TempDir(), "nope.json"), "--phases", "net",
		}, fastFlags()...)...)
		if code == 0 {
			t.Error("a missing policy file was ignored")
		}
	})
}

// The report directory carries the decision beside the evidence, because the
// directory is what one person hands another.
func TestCheckPolicyWritesPolicyJSON(t *testing.T) {
	f := newFakeServer(t)
	f.open = true
	dir := t.TempDir()
	pol := policyFixture(t, `{"version":1,"name":"recorded","must_pass":["net.dns"]}`)

	run(t, append([]string{
		"check", f.srv.URL + "/mcp", "--policy", pol, "--report-dir", dir, "--phases", "net",
	}, fastFlags()...)...)

	b, err := os.ReadFile(filepath.Join(dir, "policy.json"))
	if err != nil {
		t.Fatalf("the report directory has no policy.json: %v", err)
	}
	var got struct {
		Policy string `json:"policy"`
		OK     bool   `json:"ok"`
		Rules  []struct {
			Rule string `json:"rule"`
			Met  bool   `json:"met"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Policy != "recorded" || !got.OK || len(got.Rules) != 1 {
		t.Errorf("policy.json = %+v", got)
	}
}

// The same file has to govern a live run and the signed claim derived from it,
// or what gates a pipeline and what a gateway checks months later drift apart.
func TestVerifyPolicyAgreesWithCheckPolicy(t *testing.T) {
	endpoint, _, statement := attestFixture(t)
	att := filepath.Join(t.TempDir(), "att.json")
	if err := os.WriteFile(att, []byte(statement), 0o600); err != nil {
		t.Fatal(err)
	}
	pol := policyFixture(t, `{"version":1,"name":"shared","must_pass":["net.dns"],"target":{"transport":"http","endpoint":"`+endpoint+`"}}`)

	out, code := run(t, "verify", att, "--policy", pol)
	if code != 0 {
		t.Fatalf("exited %d: %s", code, out)
	}
	for _, want := range []string{"policy     shared", "net.dns passed", "the policy is met"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	}

	// And the JSON rendering carries it, because that is what a policy engine
	// downstream reads.
	out, code = run(t, "verify", att, "--policy", pol, "--output", "json")
	if code != 0 {
		t.Fatalf("exited %d: %s", code, out)
	}
	var v struct {
		OK     bool `json:"ok"`
		Policy *struct {
			Policy string `json:"policy"`
			OK     bool   `json:"ok"`
		} `json:"policy"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if v.Policy == nil || v.Policy.Policy != "shared" || !v.Policy.OK || !v.OK {
		t.Errorf("verification = %+v", v)
	}
}

// A policy that is not met has to fail verify, and the failure has to be
// distinguishable from an unusable statement: exit 2, not 1.
func TestVerifyPolicyFailure(t *testing.T) {
	_, _, statement := attestFixture(t)
	att := filepath.Join(t.TempDir(), "att.json")
	if err := os.WriteFile(att, []byte(statement), 0o600); err != nil {
		t.Fatal(err)
	}
	pol := policyFixture(t, `{"version":1,"name":"unreachable","min_score":100}`)

	out, code := run(t, "verify", att, "--policy", pol)
	if code != 2 {
		t.Fatalf("an unmet policy exited %d, want 2:\n%s", code, out)
	}
	if !strings.Contains(out, "the policy is not met") {
		t.Errorf("output:\n%s", out)
	}
}

// failingChecks reads the ids of every failing check out of a saved report.
func failingChecks(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var rep struct {
		Phases []struct {
			Findings []struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			} `json:"findings"`
		} `json:"phases"`
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range rep.Phases {
		for _, f := range p.Findings {
			if f.Status == "fail" {
				out = append(out, f.ID)
			}
		}
	}
	return out
}
