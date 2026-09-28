// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sra2a "satellion.com/passmcp-reporting/a2a"
)

// fakeA2A serves a minimal A2A v1 card at the well-known path and answers
// ListTasks as serve says: a task list to anyone, or 401.
func fakeA2A(t *testing.T, serve bool) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/agent-card.json":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name": "Recipe Agent", "description": "Helps with recipes.", "version": "1.0.0",
				"supportedInterfaces": []any{map[string]any{"url": srv.URL + "/rpc", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}},
				"capabilities":        map[string]any{},
				"defaultInputModes":   []any{"text/plain"},
				"defaultOutputModes":  []any{"text/plain"},
				"skills":              []any{map[string]any{"id": "find", "name": "Find", "description": "Finds.", "tags": []any{"cooking"}}},
			})
		case "/rpc":
			if !serve {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"passmcp-a2a-1","result":{"tasks":[]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestA2ACheckWritesAnAttestation runs the command end to end and verifies
// what it wrote to stdout with passmcp-reporting's offline verifier.
//
// AC: A2A-05
func TestA2ACheckWritesAnAttestation(t *testing.T) {
	srv := fakeA2A(t, false)
	out, code := run(t, "a2a", "check", srv.URL, "--output", "attestation")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	st, err := sra2a.Parse([]byte(out))
	if err != nil {
		t.Fatalf("the attestation does not verify: %v\n%s", err, out)
	}
	if !st.Covers(srv.URL) {
		t.Errorf("the statement does not cover %s", srv.URL)
	}
	if st.Predicate.Instrument.Name != "passmcp" || len(st.Predicate.Verdicts) != 4 {
		t.Errorf("predicate %+v", st.Predicate)
	}
}

func TestA2ACheckJSONAndText(t *testing.T) {
	srv := fakeA2A(t, true)
	out, code := run(t, "a2a", "check", srv.URL, "--output", "json")
	if code != 2 {
		t.Fatalf("an agent that serves anyone exited %d\n%s", code, out)
	}
	var res struct {
		CardURL  string `json:"card_url"`
		Findings []struct {
			ID, Status string
			Evidence   []string
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out)
	}
	if res.CardURL != srv.URL+"/.well-known/agent-card.json" || len(res.Findings) != 4 {
		t.Fatalf("result %+v", res)
	}
	if f := res.Findings[3]; f.ID != "a2a.unauthenticated" || f.Status != "fail" || len(f.Evidence) != 1 {
		t.Errorf("unauthenticated finding %+v", f)
	}
	out, code = run(t, "a2a", "check", srv.URL)
	if code != 2 || !strings.Contains(out, "FAIL  a2a.unauthenticated") {
		t.Errorf("text exit %d:\n%s", code, out)
	}
}

func TestA2ACheckRefusesBadInput(t *testing.T) {
	if _, code := run(t, "a2a", "check", "https://a.example", "--output", "sarif"); code == 0 {
		t.Error("an unknown --output was accepted")
	}
	if _, code := run(t, "a2a", "check", "ftp://a.example"); code == 0 {
		t.Error("a non-http URL was accepted")
	}
}
