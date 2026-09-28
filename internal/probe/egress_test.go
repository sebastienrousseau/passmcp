// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/egress"
	"satellion.com/passmcp/internal/telemetry"
)

// egressSession builds a session with a live witness.
func egressSession(t *testing.T, expect []string) *Session {
	t.Helper()
	p, err := egress.Start(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return &Session{
		Opts:  Options{Recorder: &telemetry.Recorder{}, WatchEgress: true, ExpectEgress: expect},
		Proxy: p,
	}
}

// dialThrough makes the proxy see a connection, the way a server reading
// HTTP_PROXY out of its environment would.
func dialThrough(t *testing.T, s *Session, target string) {
	t.Helper()
	u, err := url.Parse(s.Proxy.Addr())
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(u)},
	}
	res, err := c.Get(target)
	if err != nil {
		t.Fatalf("dialling %s: %v", target, err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
}

func egressFindings(t *testing.T, s *Session) map[string]Finding {
	t.Helper()
	return byFindingID(checkEgress(s))
}

// TestEgressIsSilentWithoutAWitness: this costs a proxy and an altered
// environment, so it is opt-in, and a run that did not ask for it says
// nothing rather than implying there was nothing to see.
func TestEgressIsSilentWithoutAWitness(t *testing.T) {
	s := &Session{Opts: Options{Recorder: &telemetry.Recorder{}}}
	if got := checkEgress(s); len(got) != 0 {
		t.Fatalf("want no findings without a witness, got %+v", got)
	}
}

// TestEgressPassesAServerThatWentNowhere. Worth stating: a report silent
// here reads as a check that did not run.
func TestEgressPassesAServerThatWentNowhere(t *testing.T) {
	fs := egressFindings(t, egressSession(t, nil))
	if f := fs["egress.hosts"]; f.Status != Pass {
		t.Fatalf("a server that dialled nothing did not pass: %+v", f)
	}
}

// TestEgressInventoriesWithoutAccusing is the default posture. passmcp
// cannot know which host is legitimate for a server it was handed five
// seconds ago, so it reports and does not judge.
func TestEgressInventoriesWithoutAccusing(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()

	s := egressSession(t, nil)
	dialThrough(t, s, up.URL)

	fs := egressFindings(t, s)
	hosts := fs["egress.hosts"]
	if hosts.Status != Info {
		t.Fatalf("an unjudged inventory should be information, got %s: %q", hosts.Status, hosts.Detail)
	}
	if !strings.Contains(hosts.Detail, "127.0.0.1") {
		t.Errorf("the finding does not name where it went: %q", hosts.Detail)
	}
	if len(hosts.Evidence) == 0 {
		t.Error("the destinations must be carried as evidence")
	}

	// And with nothing to measure against, the gate skips rather than
	// inventing a verdict.
	if u := fs["egress.undeclared_host"]; u.Status != Skip {
		t.Errorf("without --expect-egress the gate must skip, got %s: %q", u.Status, u.Detail)
	}
}

// TestEgressFailsAnUndeclaredHost is the whole point of the milestone: a
// server that reached somewhere the operator did not name.
func TestEgressFailsAnUndeclaredHost(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()

	s := egressSession(t, []string{"api.github.com"})
	dialThrough(t, s, up.URL)

	f := egressFindings(t, s)["egress.undeclared_host"]
	if f.Status != Fail {
		t.Fatalf("an undeclared destination did not fail: %+v", f)
	}
	if f.Severity != Critical {
		t.Errorf("severity = %v, want Critical", f.Severity)
	}
	if !strings.Contains(f.Detail, "127.0.0.1") {
		t.Errorf("the finding does not name the destination: %q", f.Detail)
	}
	if f.Advice == "" {
		t.Error("a failing egress check has to say what to do about it")
	}
}

// TestEgressPassesWhenEveryHostWasExpected.
func TestEgressPassesWhenEveryHostWasExpected(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()

	s := egressSession(t, []string{"127.0.0.1"})
	dialThrough(t, s, up.URL)

	if f := egressFindings(t, s)["egress.undeclared_host"]; f.Status != Pass {
		t.Fatalf("a declared destination did not pass: %+v", f)
	}
}

// TestEgressSaysSoWhenItCouldNotWatch. "No connections" would be a false
// reassurance, which is the one answer this must never give.
func TestEgressSaysSoWhenItCouldNotWatch(t *testing.T) {
	s := &Session{
		Opts:      Options{Recorder: &telemetry.Recorder{}, WatchEgress: true},
		egressErr: "listen: address already in use",
	}
	out := checkEgress(s)
	if len(out) != 1 || out[0].Status != Info {
		t.Fatalf("want one informational finding, got %+v", out)
	}
	if strings.Contains(out[0].Detail, "no outbound") {
		t.Errorf("a failed witness must not read as a clean result: %q", out[0].Detail)
	}
	if !strings.Contains(out[0].Detail, "already in use") {
		t.Errorf("the finding does not carry the reason: %q", out[0].Detail)
	}
}

// TestHostExpectedMatching, including the subdomain form.
func TestHostExpectedMatching(t *testing.T) {
	expected := []string{"api.github.com", ".example.com", ""}
	for host, want := range map[string]bool{
		"api.github.com":      true,
		"API.GitHub.com":      true,
		"example.com":         true,
		"cdn.example.com":     true,
		"a.b.example.com":     true,
		"notexample.com":      false,
		"github.com":          false,
		"evil.com":            false,
		"api.github.com.evil": false,
	} {
		if got := hostExpected(host, expected); got != want {
			t.Errorf("hostExpected(%q) = %v, want %v", host, got, want)
		}
	}
	if hostExpected("anything", nil) {
		t.Error("an empty expectation must match nothing")
	}
}

// TestEgressCatchesAServerPhoningHome is the milestone's own proof, end
// to end: a server that behaves impeccably in every other respect and
// quietly contacts a third host while it does. Nothing else in the report
// notices, because the destination is written down nowhere.
//
// It exercises the real path and nothing stubbed: passmcp starts the
// process, constructs its environment, injects the proxy address, and the
// fixture dials with an ordinary client honouring ProxyFromEnvironment.
//
// The destination deliberately does not resolve. Two reasons, and the
// first is not squeamishness: Go never proxies a loopback address, so a
// test server on 127.0.0.1 would bypass the witness and prove nothing —
// which is how this test failed when it was first written. The second is
// that the attempt is the finding. A server reaching for somewhere passmcp
// cannot follow is exactly as reportable as one that got through, and the
// proxy records the destination before it tries the connection.
func TestEgressCatchesAServerPhoningHome(t *testing.T) {
	const home = "telemetry.passmcp-fixture.invalid"

	_, fs := runStdioWatched(t, "phones-home", "http://"+home+"/collect")

	hosts := fs["egress.hosts"]
	if hosts.Status != Info {
		t.Fatalf("egress.hosts = %s %q, want an inventory naming the destination", hosts.Status, hosts.Detail)
	}
	if !strings.Contains(hosts.Detail, home) {
		t.Fatalf("the run did not report where the server went: %q", hosts.Detail)
	}
	if len(hosts.Evidence) == 0 {
		t.Error("the destination must be carried as evidence")
	}

	// The server itself did everything right, which is the whole point of
	// the fixture: no other check in the report has anything to say.
	if f := fs["stdio.alive"]; f.Status != Pass {
		t.Errorf("the fixture was supposed to be a well-behaved server: %+v", f)
	}
	if f := fs["stdio.stdout_clean"]; f.Status != Pass {
		t.Errorf("the fixture was supposed to keep the wire clean: %+v", f)
	}
}

// TestEgressGatesAServerPhoningHome: the same run, with the operator
// having said where the server is allowed to go.
func TestEgressGatesAServerPhoningHome(t *testing.T) {
	const home = "telemetry.passmcp-fixture.invalid"

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	s, err := Run(context.Background(), Options{
		Stdio: &passmcp.StdioConfig{
			Command: self,
			Env:     []string{fakeEnv + "=phones-home", "PASSMCP_FIXTURE_DIAL=http://" + home + "/collect"},
		},
		Recorder: telemetry.New(), Version: "t", RPS: -1, Samples: 2, Concurrency: 2,
		CallTimeout:  5 * time.Second,
		WatchEgress:  true,
		ExpectEgress: []string{"api.github.com"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	f := findingsByID(s)["egress.undeclared_host"]
	if f.Status != Fail {
		t.Fatalf("a server reaching an undeclared host did not fail: %+v", f)
	}
	if !strings.Contains(f.Detail, home) {
		t.Errorf("the finding does not name the destination: %q", f.Detail)
	}
}
