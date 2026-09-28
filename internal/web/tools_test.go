// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// toolsBody decodes the selector's answer.
type toolsBody struct {
	Tools []struct {
		Name        string `json:"name"`
		Kind        string `json:"kind"`
		Policy      string `json:"policy"`
		Description string `json:"description"`
	} `json:"tools"`
	Error string `json:"error"`
}

func postTools(t *testing.T, s *Server, ts *httptest.Server, body string) (*http.Response, toolsBody) {
	t.Helper()
	res := do(t, ts, http.MethodPost, "/api/tools?t="+s.Token(), body,
		map[string]string{"Content-Type": "application/json"})
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	var out toolsBody
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return res, out
}

// TestListToolsOffersTheSameRowsAsTheTerminal is the parity assertion: the
// browser asks for a selector and gets the catalogue classified exactly as
// the CLI's -i would classify it.
func TestListToolsOffersTheSameRowsAsTheTerminal(t *testing.T) {
	mcp := mcpServer(t)
	s, ts := newTestServer(t)

	res, body := postTools(t, s, ts, `{"target":{"endpoint":"`+mcp.URL+`"}}`)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d, body %+v", res.StatusCode, body)
	}
	if len(body.Tools) != 1 {
		t.Fatalf("want 1 tool, got %d: %+v", len(body.Tools), body.Tools)
	}
	got := body.Tools[0]
	if got.Name != "t" {
		t.Errorf("name = %q", got.Name)
	}
	// The fixture annotates readOnlyHint, so the classification and the
	// policy verdict both have to follow from it.
	if got.Kind != "read-only" {
		t.Errorf("kind = %q, want read-only", got.Kind)
	}
	if got.Policy != "allowed" {
		t.Errorf("policy = %q, want allowed", got.Policy)
	}
	if !strings.Contains(got.Description, "looks things up") {
		t.Errorf("description was not carried through: %q", got.Description)
	}
}

// TestListToolsRefusesAProgram: listing dials whatever the body names, so
// it has to refuse a command for the same reason a run does. A selector
// that would start a process the run itself is not allowed to start would
// be the hole.
func TestListToolsRefusesAProgram(t *testing.T) {
	s, ts := newTestServer(t)

	res, body := postTools(t, s, ts, `{"target":{"command":"/bin/sh","args":["-c","echo hi"]}}`)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("a program must be refused, got %d %+v", res.StatusCode, body)
	}
	if !strings.Contains(body.Error, "endpoints, not programs") {
		t.Errorf("the refusal does not say why: %q", body.Error)
	}
}

// TestListToolsInPublicModeRefusesCredentials is the ADR-0005 property, on
// the route that was added second. A read-only convenience that resolved a
// credential against the serving process would be the same leak in a
// quieter place.
func TestListToolsInPublicModeRefusesCredentials(t *testing.T) {
	mcp := mcpServer(t)
	// Built directly rather than through NewAllowlist, which requires
	// https: the fixture is a loopback httptest server.
	list := &Allowlist{origins: map[string]string{}}
	o, err := originKey(mcp.URL)
	if err != nil {
		t.Fatal(err)
	}
	list.origins[o] = "fixture"
	s, err := New(Options{
		Version: "test", Public: true, Allowed: list,
		RatePerMinute: 600, RateBurst: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)

	res, body := postTools(t, s, ts, `{"target":{"endpoint":"`+mcp.URL+`"},"credentials":{"mode":"bearer","token_env":"HOME"}}`)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("a credential must be refused in public mode, got %d %+v", res.StatusCode, body)
	}
	if !strings.Contains(body.Error, "no credentials") {
		t.Errorf("the refusal does not say why: %q", body.Error)
	}
}

// TestListToolsInPublicModeRefusesAnEndpointItWasNotGiven: the allowlist
// is what stops this being an open proxy, and it has to cover the selector
// too.
func TestListToolsInPublicModeRefusesAnEndpointItWasNotGiven(t *testing.T) {
	mcp := mcpServer(t)
	// Built directly rather than through NewAllowlist, which requires
	// https: the fixture is a loopback httptest server.
	list := &Allowlist{origins: map[string]string{}}
	o, err := originKey(mcp.URL)
	if err != nil {
		t.Fatal(err)
	}
	list.origins[o] = "fixture"
	s, err := New(Options{
		Version: "test", Public: true, Allowed: list,
		RatePerMinute: 600, RateBurst: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)

	res, body := postTools(t, s, ts, `{"target":{"endpoint":"https://example.invalid/mcp"}}`)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("an endpoint outside the allowlist must be refused, got %d %+v", res.StatusCode, body)
	}
}

// TestListToolsRejectsRubbish: the same validator the CLI uses, so a
// browser gets the CLI's error rather than a second opinion.
func TestListToolsRejectsRubbish(t *testing.T) {
	s, ts := newTestServer(t)

	res, _ := postTools(t, s, ts, `{`)
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed JSON: status %d, want 400", res.StatusCode)
	}

	res, _ = postTools(t, s, ts, `{"target":{"endpoint":"not a url"}}`)
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid endpoint: status %d, want 400", res.StatusCode)
	}
}

// TestListToolsReportsAnUnreachableServerAsTheTargetsFault: a selector
// that cannot connect is a fact about the target, and 502 says so.
func TestListToolsReportsAnUnreachableServerAsTheTargetsFault(t *testing.T) {
	s, ts := newTestServer(t)

	res, body := postTools(t, s, ts, `{"target":{"endpoint":"http://127.0.0.1:1/mcp"}}`)
	if res.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d, want 502: %+v", res.StatusCode, body)
	}
	if body.Error == "" {
		t.Error("the failure has to say what went wrong")
	}
}
