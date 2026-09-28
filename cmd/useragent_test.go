// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import "testing"

// AC: REG-05
// The registry scorecard publishes the User-Agent it checks servers with,
// so every request of a run must carry it: the client's, the unauthenticated
// first contact on the bare transport (ADR-0001) and the discovery of the
// authorization server. Before --user-agent, two requests a run went out as
// Go's default.
func TestUserAgentFlagReachesEveryRequest(t *testing.T) {
	f := newFakeServer(t)
	const ua = "passmcp-registry/0.0.1 (+https://github.com/sebastienrousseau/passmcp-registry)"
	run(t, baselineArgs(f.srv.URL+"/mcp", "--user-agent", ua)...)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.agents) < 3 {
		t.Fatalf("expected a run's worth of requests, saw %d", len(f.agents))
	}
	for i, got := range f.agents {
		if got != ua {
			t.Errorf("request %d carried User-Agent %q, not %q", i+1, got, ua)
		}
	}
}

func TestWithoutUserAgentFlagGoDefaultIsUnchanged(t *testing.T) {
	f := newFakeServer(t)
	run(t, baselineArgs(f.srv.URL+"/mcp")...)
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, got := range f.agents {
		if got != "Go-http-client/1.1" {
			t.Errorf("request %d carried User-Agent %q without the flag", i+1, got)
		}
	}
}
