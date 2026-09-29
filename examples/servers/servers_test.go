// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/telemetry"
)

// check runs passmcp's engine against the server for flaw, as `passmcp
// check` would with no credentials, and returns every finding worse than
// info by id.
func check(t *testing.T, flaw string) map[string]probe.Status {
	t.Helper()
	srv := httptest.NewServer(newServer(flaw))
	t.Cleanup(srv.Close)
	s, err := probe.Run(context.Background(), probe.Options{
		Endpoint: srv.URL + "/mcp", Creds: &creds.Credentials{Mode: creds.ModeNone},
		Recorder: telemetry.New(), HTTPClient: srv.Client(), Version: "examples",
		RPS: -1, Samples: 2, Concurrency: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	bad := map[string]probe.Status{}
	for _, p := range s.Results {
		if p.Skipped != "" {
			t.Errorf("phase %s skipped: %s", p.Name, p.Skipped)
		}
		for _, f := range p.Findings {
			if f.Status == probe.Warn || f.Status == probe.Fail {
				bad[f.ID] = f.Status
			}
		}
	}
	return bad
}

// TestEachFlawIsCaughtByItsCheck is the claim the catalogue makes: every
// server draws exactly the baseline's warnings plus the one its flaw names,
// with the status the table says. A server that tripped a second check
// would be demonstrating two things, and the table would be wrong about it.
func TestEachFlawIsCaughtByItsCheck(t *testing.T) {
	for _, f := range Flaws {
		t.Run(f.Name, func(t *testing.T) {
			want := map[string]probe.Status{}
			for _, b := range BaselineWarnings {
				want[b.Check] = probe.Warn
			}
			if f.Check != "" {
				want[f.Check] = probe.Status(f.Status)
			}
			got := check(t, f.Name)
			if !equal(got, want) {
				t.Errorf("findings worse than info:\n got %s\nwant %s", show(got), show(want))
			}
		})
	}
}

func equal(a, b map[string]probe.Status) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func show(m map[string]probe.Status) string {
	var s []string
	for k, v := range m {
		s = append(s, k+"="+string(v))
	}
	sort.Strings(s)
	return strings.Join(s, " ")
}

func TestCatalogueIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for i, f := range Flaws {
		if seen[f.Name] {
			t.Errorf("%s listed twice", f.Name)
		}
		seen[f.Name] = true
		if (i == 0) != (f.Name == Baseline) {
			t.Errorf("the baseline must be first, and only once")
		}
		if f.Name != Baseline && (f.Check == "" || (f.Status != "fail" && f.Status != "warn")) {
			t.Errorf("%s names no check, or a status other than fail or warn", f.Name)
		}
		if f.What == "" {
			t.Errorf("%s does not say what it does", f.Name)
		}
	}
}

func TestList(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"-list"}, &out, nil); err != nil {
		t.Fatal(err)
	}
	for _, f := range Flaws {
		if !strings.Contains(out.String(), f.Name) {
			t.Errorf("-list omits %s", f.Name)
		}
	}
	for _, b := range BaselineWarnings {
		if !strings.Contains(out.String(), b.Check) {
			t.Errorf("-list omits the baseline warning %s", b.Check)
		}
	}
}

func TestRunServesTheNamedFlaw(t *testing.T) {
	var got *http.Server
	stub := func(srv *http.Server) error {
		got = srv
		return http.ErrServerClosed
	}
	var out bytes.Buffer
	if err := run([]string{"-flaw", "wrong-id", "-addr", "127.0.0.1:0"}, &out, stub); err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Addr != "127.0.0.1:0" || got.Handler == nil || got.ReadHeaderTimeout == 0 ||
		!strings.Contains(out.String(), `"wrong-id"`) {
		t.Errorf("served %+v, printed %q", got, out.String())
	}

	if err := run([]string{"-flaw", "nonesuch"}, &out, stub); err == nil {
		t.Error("an unknown flaw was accepted")
	}
	if err := run([]string{"-bogus"}, &out, stub); err == nil {
		t.Error("an unknown flag was accepted")
	}
	boom := errors.New("address in use")
	if err := run(nil, &out, func(*http.Server) error { return boom }); !errors.Is(err, boom) {
		t.Errorf("a listen error was lost: %v", err)
	}
}

// TestEdgesTheEngineDoesNotReach covers the answers passmcp's run never
// asks for, so a reader can trust them too.
func TestEdgesTheEngineDoesNotReach(t *testing.T) {
	h := newServer(Baseline)
	cases := []struct {
		name, method, origin, accept, session, version, body string
		want                                                 int
	}{
		{"foreign origin", "POST", "https://evil.example", "*/*", "", "", `{}`, http.StatusForbidden},
		{"unparsable origin", "POST", "::", "*/*", "", "", `{}`, http.StatusForbidden},
		{"local origin", "POST", "http://localhost:3000", "*/*", "", "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`, http.StatusOK},
		{"GET", "GET", "", "", "", "", "", http.StatusMethodNotAllowed},
		{"DELETE", "DELETE", "", "", "x", "", "", http.StatusNoContent},
		{"no session", "POST", "", "*/*", "", "", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, http.StatusBadRequest},
		{"unknown session", "POST", "", "*/*", "nope", "", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, http.StatusNotFound},
		{"bad accept", "POST", "", "text/html", "", "", `{}`, http.StatusNotAcceptable},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, "/mcp", strings.NewReader(c.body))
		for k, v := range map[string]string{"Origin": c.origin, "Accept": c.accept, "Mcp-Session-Id": c.session, "MCP-Protocol-Version": c.version} {
			if v != "" {
				req.Header.Set(k, v)
			}
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s: HTTP %d, want %d: %s", c.name, rec.Code, c.want, rec.Body)
		}
	}
}

// TestToolCallEdges covers the tools/call answers passmcp's run does not
// provoke on every server.
func TestToolCallEdges(t *testing.T) {
	s := newServer("toxic-pair").(*server)
	for _, c := range []struct{ params, want string }{
		{`{}`, "needs params.name"},
		{`{"name":"read_inbox"}`, "No messages"},
		{`{"name":"send_email","arguments":{"to":"a@example.invalid","body":"x"}}`, "Not sent"},
		{`{"name":"nonesuch"}`, "unknown tool"},
		{`{"name":"define","arguments":{}}`, `\"word\" is required`},
	} {
		rec := httptest.NewRecorder()
		s.call(rec, rpcRequest{ID: []byte("1"), Params: []byte(c.params)})
		if !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("%s: %s, want it to contain %s", c.params, rec.Body, c.want)
		}
	}
}
