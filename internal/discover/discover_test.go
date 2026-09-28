// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package discover

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp-reporting/graph"
	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/report"
	"satellion.com/passmcp/internal/telemetry"
)

// run discovers over the given targets with no pacing.
func run(t *testing.T, targets ...Target) (*Result, *telemetry.Recorder) {
	t.Helper()
	rec := telemetry.New()
	res := Run(context.Background(), Options{Targets: targets, Recorder: rec, Concurrency: 4, Timeout: 5 * time.Second})
	return res, rec
}

// target names a URL from a targets file.
func target(u string) Target {
	return Target{URL: u, Source: Source{Type: SourceTargets, Ref: "targets.txt"}}
}

// eventAt returns the recorded request with sequence number seq.
func eventAt(t *testing.T, rec *telemetry.Recorder, seq int) telemetry.Event {
	t.Helper()
	for _, e := range rec.Events() {
		if e.Seq == seq {
			return e
		}
	}
	t.Fatalf("no request req#%d in the telemetry", seq)
	return telemetry.Event{}
}

// AC: DISC-01
func TestDiscoverProbesOnlyNamedTargetsAndCitesTheProof(t *testing.T) {
	session := (&fakeMCP{}).start(t)
	sse := (&fakeMCP{sse: true, path: "/sse"}).start(t)
	stateless := (&fakeMCP{stateless: true}).start(t)
	carded := (&fakeMCP{path: "/custom/endpoint", card: map[string]any{"remotes": []any{map[string]any{"url": "/custom/endpoint"}}}}).start(t)

	res, rec := run(t, target(session.url()), target(sse.url()), target(stateless.url()), target(carded.url()))

	want := map[string]string{
		session.url() + "/mcp":            "initialize",
		sse.url() + "/sse":                "initialize",
		stateless.url() + "/mcp":          "server/discover",
		carded.url() + "/custom/endpoint": "initialize",
	}
	if len(res.Endpoints) != len(want) {
		t.Fatalf("found %d endpoints, want %d: %+v", len(res.Endpoints), len(want), res.Endpoints)
	}
	for _, e := range res.Endpoints {
		method, ok := want[e.URL]
		if !ok {
			t.Fatalf("unexpected endpoint %s", e.URL)
		}
		if e.Method != method {
			t.Errorf("%s proven by %s, want %s", e.URL, e.Method, method)
		}
		// The proof is the request whose answer showed it: the right
		// method, to the right URL, and answered.
		ev := eventAt(t, rec, e.Proof)
		if ev.URL != e.URL || !strings.HasPrefix(ev.Label, method+" ") || ev.Status != 200 {
			t.Errorf("%s cites req#%d = %s %s (%d), not its %s", e.URL, e.Proof, ev.Label, ev.URL, ev.Status, method)
		}
	}
	for _, e := range res.Endpoints {
		if e.URL == stateless.url()+"/mcp" && (e.Server != "stateless-mcp" || e.Protocol != "2026-07-28") {
			t.Errorf("stateless endpoint recorded as %q %q", e.Server, e.Protocol)
		}
	}
	// Every request went to a named host.
	named := map[string]bool{}
	for _, s := range []*fakeMCP{session, sse, stateless, carded} {
		u, _ := url.Parse(s.url())
		named[u.Host] = true
	}
	for _, ev := range rec.Events() {
		u, _ := url.Parse(ev.URL)
		if !named[u.Host] {
			t.Errorf("contacted %s, which nobody named", ev.URL)
		}
	}
}

// AC: DISC-01
func TestDiscoverDoesNotCountAnAnswerThatIsNotMCP(t *testing.T) {
	notMCP := (&fakeMCP{path: "/elsewhere"}).start(t)
	res, _ := run(t, target(notMCP.url()))
	if len(res.Endpoints) != 0 {
		t.Fatalf("a server with no MCP endpoint at the probed paths was reported: %+v", res.Endpoints)
	}
}

// AC: DISC-02
func TestDiscoverNeverContactsAHostNobodyNamed(t *testing.T) {
	outside := (&fakeMCP{}).start(t)
	redirector := (&fakeMCP{redirect: outside.url() + "/mcp", path: "/other"}).start(t)
	cardOut := (&fakeMCP{path: "/none", card: map[string]any{"url": outside.url() + "/mcp"}}).start(t)

	res, rec := run(t, target(redirector.url()), target(cardOut.url()))

	if n := outside.hits.Load(); n != 0 {
		t.Fatalf("the out-of-scope host received %d requests", n)
	}
	if len(res.Endpoints) != 0 {
		t.Errorf("an endpoint was reported through an out-of-scope host: %+v", res.Endpoints)
	}
	u, _ := url.Parse(outside.url())
	if !slices.Contains(res.Blocked, hostKey(u)) {
		t.Errorf("blocked hosts %v do not name the out-of-scope host %s", res.Blocked, hostKey(u))
	}
	for _, ev := range rec.Events() {
		if strings.HasPrefix(ev.URL, outside.url()) {
			t.Errorf("the telemetry shows a request to %s", ev.URL)
		}
	}
}

// AC: DISC-03
func TestDiscoverReportsAnEndpointExposedWithoutAuth(t *testing.T) {
	open := (&fakeMCP{}).start(t)
	guarded := (&fakeMCP{hideTools: true}).start(t)
	protected := (&fakeMCP{auth: true}).start(t)
	res, rec := run(t, target(open.url()), target(guarded.url()), target(protected.url()))

	var exposed *Endpoint
	for i, e := range res.Endpoints {
		if e.URL == open.url()+"/mcp" {
			exposed = &res.Endpoints[i]
		} else if e.Exposed {
			t.Errorf("%s reported exposed, but it refused tools/list", e.URL)
		}
	}
	if exposed == nil || !exposed.Exposed || exposed.Tools != 2 {
		t.Fatalf("the open endpoint was not reported exposed: %+v", exposed)
	}
	ev := eventAt(t, rec, exposed.ExposedProof)
	if !strings.HasPrefix(ev.Label, "tools/list ") || ev.RequestHeaders["Authorization"] != "" {
		t.Errorf("the exposure proof req#%d is %q with Authorization %q, not an unauthenticated tools/list",
			exposed.ExposedProof, ev.Label, ev.RequestHeaders["Authorization"])
	}
	if len(res.Protected) != 1 || res.Protected[0].URL != protected.url()+"/mcp" || res.Protected[0].Metadata == "" {
		t.Errorf("the 401 endpoint was not listed apart with its resource metadata: %+v", res.Protected)
	}
	if res.Exposed() != 1 {
		t.Errorf("Exposed() = %d, want 1", res.Exposed())
	}
	// Discovery itself never calls a tool.
	for _, s := range []*fakeMCP{open, guarded, protected} {
		if slices.Contains(s.called(), "tools/call") {
			t.Errorf("discovery called a tool on %s", s.url())
		}
	}

	var text, sarif bytes.Buffer
	WriteText(&text, res)
	if err := WriteSARIF(&sarif, res, "test"); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"text": text.String(), "sarif": sarif.String()} {
		if !strings.Contains(out, "critical: exposed without authentication") || !strings.Contains(out, "req#") {
			t.Errorf("%s output does not report the exposure with its request:\n%s", name, out)
		}
	}
}

// AC: DISC-03
func TestValidateRunsTheReadOnlyCheckAndWritesAnAttestation(t *testing.T) {
	open := (&fakeMCP{}).start(t)
	res, _ := run(t, target(open.url()))
	dir := t.TempDir()
	// The real check, not a stand-in: the engine against the fake.
	check := EngineChecker("test", 0, 1)
	if err := Validate(context.Background(), res, check, dir); err != nil {
		t.Fatal(err)
	}
	v := res.Endpoints[0].Attestation
	if v == nil || v.Error != "" || v.File == "" || v.Digest == "" {
		t.Fatalf("no attestation: %+v", v)
	}
	b, err := os.ReadFile(v.File)
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if err := json.Unmarshal(b, &st); err != nil || st["predicateType"] == nil {
		t.Fatalf("the attestation is not an in-toto statement: %v %s", err, b)
	}
	if graph.Digest(b) != v.Digest {
		t.Errorf("digest %s does not cover the file's bytes", v.Digest)
	}
	// ADR 0004: the check calls the read-only tool and never the one
	// without readOnlyHint.
	calls := open.called()
	if !slices.Contains(calls, "tools/call:read_notes") {
		t.Errorf("the full check did not run: read_notes was never called (%v)", calls)
	}
	if slices.Contains(calls, "tools/call:delete_everything") {
		t.Errorf("validation invoked a tool without readOnlyHint")
	}
}

// AC: DISC-03
func TestValidateKeepsAFailedCheckOnItsEndpoint(t *testing.T) {
	open := (&fakeMCP{}).start(t)
	res, _ := run(t, target(open.url()))
	failing := func(context.Context, string) (*report.Report, error) {
		return nil, context.DeadlineExceeded
	}
	if err := Validate(context.Background(), res, failing, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if v := res.Endpoints[0].Attestation; v == nil || v.Error == "" {
		t.Fatalf("a check that failed left no reason: %+v", v)
	}
}

// AC: DISC-04
func TestSourcesBecomeTargetsTaggedWithWhereTheyCameFrom(t *testing.T) {
	claude := []byte(`{"mcpServers": {"notes": {"url": "https://notes.example/mcp"}, "local": {"command": "npx", "args": ["x"]}}}`)
	vscode := []byte(`{
	  // VS Code writes comments
	  "mcp": {"servers": {"crm": {"type": "http", "url": "https://crm.example/mcp",},},},
	}`)
	zed := []byte(`{"context_servers": {"docs": {"url": "https://docs.example/sse"}}}`)
	for name, b := range map[string][]byte{"claude.json": claude, "settings.json": vscode, "zed.json": zed} {
		got, err := FromClientConfig(b, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != 1 || got[0].Source != (Source{Type: SourceConfig, Ref: name}) {
			t.Errorf("%s gave %+v", name, got)
		}
	}
	gw := []byte("binds:\n- listeners:\n  - routes:\n    - backends:\n      - mcp:\n          targets:\n          - name: a\n            mcp:\n              host: https://gw-a.example/mcp\n          - name: b\n            sse:\n              host: \"http://gw-b.example:8080/sse\"\n")
	got := FromGatewayConfig(gw, "agentgateway.yaml")
	if len(got) != 2 || got[0].Source.Type != SourceGateway || got[0].URL != "http://gw-b.example:8080/sse" {
		t.Errorf("gateway gave %+v", got)
	}
}

// AC: DISC-04
func TestRegistrySourceStaysInsideTheOperatorsNamespace(t *testing.T) {
	reg := newFakeRegistry(t)
	got, err := FromRegistry(context.Background(), reg.Client(), reg.URL, "io.github.acme")
	if err != nil {
		t.Fatal(err)
	}
	var urls []string
	for _, t2 := range got {
		urls = append(urls, t2.URL)
		if t2.Source != (Source{Type: SourceRegistry, Ref: "io.github.acme"}) {
			t.Errorf("registry target tagged %+v", t2.Source)
		}
	}
	want := []string{"https://acme.example/mcp", "https://acme2.example/mcp"}
	if !slices.Equal(urls, want) {
		t.Fatalf("registry targets %v, want %v (the other publisher's server must be dropped)", urls, want)
	}
	for _, broad := range []string{"", "io.github", "*", "io"} {
		if _, err := FromRegistry(context.Background(), reg.Client(), reg.URL, broad); err == nil {
			t.Errorf("namespace %q was accepted", broad)
		}
	}
}

// AC: DISC-05
func TestStateReportsNewAndDisappearedEndpoints(t *testing.T) {
	a := (&fakeMCP{}).start(t)
	b := (&fakeMCP{}).start(t)
	elsewhere := "https://not-probed.example/mcp"
	state := &State{Version: stateVersion, Endpoints: map[string]StateEntry{
		elsewhere: {FirstSeen: time.Unix(1, 0), LastSeen: time.Unix(2, 0)},
	}}

	first, _ := run(t, target(a.url()), target(b.url()))
	state.Compare(first)
	for _, e := range first.Endpoints {
		if e.Status != StatusNew {
			t.Errorf("first sight of %s is %s, want new", e.URL, e.Status)
		}
	}
	lastSeenB := state.Endpoints[b.url()+"/mcp"].LastSeen

	b.srv.Close()
	c := (&fakeMCP{}).start(t)
	second, _ := run(t, target(a.url()), target(b.url()), target(c.url()))
	state.Compare(second)

	status := map[string]Status{}
	for _, e := range second.Endpoints {
		status[e.URL] = e.Status
	}
	if status[a.url()+"/mcp"] != StatusSeen || status[c.url()+"/mcp"] != StatusNew {
		t.Errorf("statuses %v: a should be seen, c new", status)
	}
	if len(second.Disappeared) != 1 || second.Disappeared[0].URL != b.url()+"/mcp" {
		t.Fatalf("disappeared %+v, want only b", second.Disappeared)
	}
	if !second.Disappeared[0].LastSeen.Equal(lastSeenB) || second.Disappeared[0].Status != StatusDisappeared {
		t.Errorf("b disappeared with last seen %v, want %v", second.Disappeared[0].LastSeen, lastSeenB)
	}

	// Round trip through a file, as the command does.
	path := filepath.Join(t.TempDir(), "state.json")
	if err := state.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadState(path)
	if err != nil || len(loaded.Endpoints) != len(state.Endpoints) {
		t.Fatalf("state did not round-trip: %v %d", err, len(loaded.Endpoints))
	}
}

// AC: DISC-06
func TestValidatedEndpointsLandInTheGraphIdempotently(t *testing.T) {
	open := (&fakeMCP{}).start(t)
	res, _ := run(t, target(open.url()))
	res.Endpoints[0].Sources = append(res.Endpoints[0].Sources, Source{Type: SourceConfig, Ref: "cursor.json"})
	stub := func(context.Context, string) (*report.Report, error) { return stubReport(open.url() + "/mcp"), nil }
	if err := Validate(context.Background(), res, stub, t.TempDir()); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := SaveGraph(dir, res); err != nil {
		t.Fatal(err)
	}
	once, err := os.ReadFile(filepath.Join(dir, graph.FileName))
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveGraph(dir, res); err != nil {
		t.Fatal(err)
	}
	twice, _ := os.ReadFile(filepath.Join(dir, graph.FileName))
	if !bytes.Equal(once, twice) {
		t.Fatalf("applying the same result twice changed the graph")
	}

	g, err := graph.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	sid := graph.ServerID("http", open.url()+"/mcp")
	n, ok := g.Node(sid)
	if !ok || n.Server == nil || n.Server.Attestation != res.Endpoints[0].Attestation.Digest || n.Server.Grade != "C" {
		t.Fatalf("server node %+v, validation %+v", n.Server, res.Endpoints[0].Attestation)
	}
	if got := g.EdgesFrom(sid, graph.DiscoveredBy); len(got) != 2 {
		t.Errorf("discovered_by edges %+v, want one per source", got)
	}
	if got := g.EdgesFrom(sid, graph.AttestedBy); len(got) != 1 || got[0].To != graph.AttestationID(res.Endpoints[0].Attestation.Digest) {
		t.Errorf("attested_by edges %+v", got)
	}
	if got := g.EdgesFrom(sid, graph.Exposes); len(got) != 2 {
		t.Errorf("exposes edges %+v, want the two tools", got)
	}
}

// stubReport is a finished report with one failing check and two tools.
func stubReport(endpoint string) *report.Report {
	return &report.Report{
		Passmcp: report.Meta{Version: "test", SchemaVersion: report.SchemaVersion},
		Target:  report.Target{Endpoint: endpoint, Scheme: "http", Transport: "http"},
		Started: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC),
		Score:   report.Score{Total: 61, Grade: "C"},
		Counts:  report.Counts{Fail: 1},
		Catalog: report.Catalog{Tools: []report.ToolSummary{
			{Name: "read_notes", Annotated: true, ReadOnly: true},
			{Name: "delete_everything"},
		}},
		Phases: []probe.PhaseResult{{Name: "auth", Findings: []probe.Finding{
			{ID: "auth.unauthenticated_tools", Status: probe.Fail, Severity: probe.Critical},
		}}},
	}
}

// AC: DISC-07
func TestDiscoverRespectsRPS(t *testing.T) {
	srv := (&fakeMCP{}).start(t)
	rec := telemetry.New()
	start := time.Now()
	Run(context.Background(), Options{Targets: []Target{target(srv.url())}, Recorder: rec, RPS: 20, Concurrency: 1})
	n := rec.Count()
	if n < 4 {
		t.Fatalf("only %d requests; the pacing test needs several", n)
	}
	min := time.Duration(n-1) * time.Second / 20
	if elapsed := time.Since(start); elapsed < min-10*time.Millisecond {
		t.Fatalf("%d requests in %v at --rps 20; at least %v expected", n, elapsed, min)
	}
}

// AC: DISC-07
func TestDiscoverRespectsConcurrency(t *testing.T) {
	var servers []*fakeMCP
	var targets []Target
	for range 4 {
		s := (&fakeMCP{delay: 20 * time.Millisecond}).start(t)
		servers = append(servers, s)
		targets = append(targets, target(s.url()))
	}
	// A shared counter across servers: one target at a time means one
	// request in flight across all of them.
	var shared fakeCounter
	for _, s := range servers {
		h := s.srv.Config.Handler
		s.srv.Config.Handler = shared.wrap(h)
	}
	Run(context.Background(), Options{Targets: targets, Recorder: telemetry.New(), Concurrency: 1})
	if shared.max() != 1 {
		t.Fatalf("%d requests in flight at --concurrency 1", shared.max())
	}
	shared.reset()
	Run(context.Background(), Options{Targets: targets, Recorder: telemetry.New(), Concurrency: 3})
	if m := shared.max(); m < 2 || m > 3 {
		t.Fatalf("%d requests in flight at --concurrency 3", m)
	}
}

// AC: DISC-07
func TestDiscoveryWritesJSONAndSARIF(t *testing.T) {
	open := (&fakeMCP{}).start(t)
	res, _ := run(t, target(open.url()))
	res.Disappeared = []Endpoint{{URL: "https://gone.example/mcp", LastSeen: time.Unix(0, 0), Status: StatusDisappeared}}
	var js, sa bytes.Buffer
	if err := WriteJSON(&js, res); err != nil {
		t.Fatal(err)
	}
	var back Result
	if err := json.Unmarshal(js.Bytes(), &back); err != nil || len(back.Endpoints) != 1 {
		t.Fatalf("JSON does not round-trip: %v", err)
	}
	if err := WriteSARIF(&sa, res, "test"); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(sa.Bytes(), &log); err != nil || log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("not SARIF 2.1.0: %v", err)
	}
	rules := map[string]int{}
	for _, r := range log.Runs[0].Results {
		rules[r.RuleID]++
		if r.PartialFingerprints["passmcpDiscovery/v1"] == "" {
			t.Errorf("result %s has no fingerprint", r.RuleID)
		}
	}
	if rules[RuleEndpoint] != 1 || rules[RuleExposed] != 1 || rules[RuleDisappeared] != 1 {
		t.Errorf("SARIF results by rule %v", rules)
	}
}
