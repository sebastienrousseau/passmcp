// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

// FuzzRunSpecJSON drives the surface the web UI will expose.
//
// Once a browser can post a RunSpec, the spec decoder is reachable by
// anything that can reach the listener. Three properties have to hold for
// every input: decoding must not panic, validation must decide rather than
// hang, and a spec that validates must be one the engine can actually run —
// there is no second check between Validate and the first request.
func FuzzRunSpecJSON(f *testing.F) {
	seeds := []string{
		`{}`,
		`{"target":{"endpoint":"https://mcp.example.com/mcp"}}`,
		`{"target":{"endpoint":"https://x/mcp"},"pacing":{"samples":-1,"concurrency":-5,"rps":-1}}`,
		`{"target":{"endpoint":"https://x/mcp"},"phases":{"only":["net"],"skip":["catalog"]}}`,
		`{"target":{"endpoint":"\u0000"},"output":{"format":"html"}}`,
		`{"target":{"endpoint":"https://x/mcp"},"pacing":{"call_timeout_ns":-9223372036854775808}}`,
		`{"target":{"endpoint":"file:///etc/passwd"}}`,
		`{"target":{"endpoint":"https://x/mcp"},"policy":{"tool_args":{"a":{"b":[1,2,{"c":null}]}}}}`,
		`{"credentials":{"token":"leaked"},"target":{"endpoint":"https://x/mcp"}}`,
		`[]`,
		`null`,
		`{"target":{"endpoint":"https://x/mcp"},"pacing":{"samples":2147483647,"max_resources":2147483647}}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		var spec RunSpec
		if err := json.Unmarshal([]byte(raw), &spec); err != nil {
			return // malformed JSON is the caller's problem, not a defect
		}
		spec = spec.WithDefaults()

		// Validate must terminate with a decision for every input.
		err := spec.Validate()

		// A spec that crossed a network must never have carried a secret,
		// whatever the sender put in the document.
		if spec.Creds.Token != "" || spec.Creds.ClientSecret != "" || spec.Creds.Basic != "" || len(spec.Creds.Headers) > 0 {
			t.Errorf("a decoded spec carried a secret field: %+v", spec.Creds)
		}

		if err != nil {
			return
		}

		// Having validated, the spec must be runnable: defaults applied,
		// no value that would make the probe layer misbehave.
		if spec.Output.Format == "" || !spec.Output.Format.Valid() {
			t.Errorf("validated with an unusable format %q", spec.Output.Format)
		}
		if spec.Target.Endpoint == "" {
			t.Error("validated with no endpoint")
		}
		for _, name := range append(append([]string{}, spec.Phases.Only...), spec.Phases.Skip...) {
			if !knownPhase(name) {
				t.Errorf("validated with unknown phase %q", name)
			}
		}
		// A validated spec must round-trip, or the web UI cannot echo back
		// what it is about to run.
		b, err := json.Marshal(spec)
		if err != nil {
			t.Fatalf("a validated spec must re-encode: %v", err)
		}
		var again RunSpec
		if err := json.Unmarshal(b, &again); err != nil {
			t.Fatalf("a validated spec must round-trip: %v", err)
		}
		if again.Target.Endpoint != spec.Target.Endpoint {
			t.Errorf("endpoint changed across a round trip: %q -> %q", spec.Target.Endpoint, again.Target.Endpoint)
		}
	})
}

// FuzzCredentialRedaction drives the credential half specifically: whatever
// a caller puts in a spec, serialising it must not emit the value.
func FuzzCredentialRedaction(f *testing.F) {
	f.Add("tok", "sec", "user:pass", "X-Api-Key", "header-value")
	f.Add("", "", "", "", "")
	f.Add("\u0000", `"`, `\`, "\n", "</script>")

	f.Fuzz(func(t *testing.T, token, secret, basic, hdrName, hdrVal string) {
		spec := RunSpec{
			Target: TargetSpec{Endpoint: "https://x/mcp"},
			Creds: CredSpec{
				Token: token, ClientSecret: secret, Basic: basic,
				Headers: map[string]string{hdrName: hdrVal},
			},
		}
		b, err := json.Marshal(spec)
		if err != nil {
			t.Fatalf("a spec must always encode: %v", err)
		}
		out := string(b)
		for name, secretVal := range map[string]string{"token": token, "client secret": secret, "basic": basic, "header value": hdrVal} {
			if len(secretVal) < 4 {
				continue // too short to distinguish from incidental text
			}
			if strings.Contains(out, secretVal) {
				t.Errorf("a serialised spec leaked the %s: %q in %s", name, secretVal, out)
			}
		}
		// And String, which goes into logs.
		if len(token) >= 4 && strings.Contains(spec.String(), token) {
			t.Errorf("String leaked the token: %q", spec.String())
		}
	})
}
