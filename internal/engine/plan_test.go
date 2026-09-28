// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"encoding/json"
	"net/url"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"satellion.com/passmcp/internal/policy"
	"satellion.com/passmcp/internal/telemetry"
)

// A statement is made to be handed on, so its plan carries names and never
// a value: not a token, a client secret, basic credentials, a header, a
// token-endpoint parameter, nor a registered secret wherever it sits.
func TestPlanCarriesNoSecret(t *testing.T) {
	red := &telemetry.Redactor{}
	red.Add("sk-registered-secret")
	spec := RunSpec{
		Target: TargetSpec{Command: "server", Args: []string{"--api-key=sk-registered-secret"}},
		Creds: CredSpec{
			Mode: "client-credentials", Token: "tok-value", ClientID: "cid",
			ClientSecret: "cs-value", Basic: "u:pw-value",
			Headers: map[string]string{"X-API-Key": "hdr-value"},
			Params:  url.Values{"client_assertion": {"param-value"}},
		},
		Policy: PolicySpec{ToolArgs: map[string]map[string]any{"t": {"q": "sk-registered-secret"}}},
		Output: OutputSpec{ReportDir: "/tmp/reports"},
		Gate:   &policy.Policy{},
	}
	p := spec.Plan(red)
	if p == nil {
		t.Fatal("no plan")
	}
	for _, v := range []string{"tok-value", "cs-value", "pw-value", "hdr-value", "param-value", "sk-registered-secret", "/tmp/reports"} {
		if strings.Contains(string(p.Spec), v) {
			t.Errorf("the plan carries %q:\n%s", v, p.Spec)
		}
	}
	want := []string{"token", "client secret", "basic", "header X-API-Key", "param client_assertion"}
	if !reflect.DeepEqual(p.ByValue, want) {
		t.Errorf("by value = %v, want %v", p.ByValue, want)
	}
	if p.Credentials != "client-credentials" || p.OS != runtime.GOOS || p.Arch != runtime.GOARCH {
		t.Errorf("plan = %+v", p)
	}
	back, err := SpecFromPlan(p)
	if err != nil {
		t.Fatal(err)
	}
	if back.Creds.ClientID != "cid" || back.Target.Command != "server" || back.Gate != nil {
		t.Errorf("round trip lost what measures the run: %+v", back)
	}
}

// A mask that landed on JSON syntax would make the plan unreadable; it is
// dropped rather than written broken.
func TestPlanThatMaskingWouldBreakIsDropped(t *testing.T) {
	red := &telemetry.Redactor{}
	red.Add(`},"credentials":`)
	if p := (RunSpec{Target: TargetSpec{Endpoint: "https://x.example/mcp"}}).Plan(red); p != nil {
		t.Errorf("a broken plan was kept: %s", p.Spec)
	}
}

func TestPlanRecordsTheKernelWhereItCan(t *testing.T) {
	k := kernelRelease()
	if (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && k == "" {
		t.Error("no kernel release on a platform that publishes one")
	}
	var p struct {
		Kernel string `json:"kernel"`
	}
	b, _ := json.Marshal(RunSpec{}.Plan(&telemetry.Redactor{}))
	_ = json.Unmarshal(b, &p)
	if p.Kernel != k {
		t.Errorf("plan kernel %q, running %q", p.Kernel, k)
	}
}
