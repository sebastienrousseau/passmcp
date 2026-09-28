// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp-reporting/graph"
	"satellion.com/passmcp/internal/discover"
	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/report"
)

// openMCP is an MCP endpoint at /mcp that lists its tools to anyone.
func openMCP(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var req struct {
			ID     *int64 `json:"id"`
			Method string `json:"method"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &req)
		if req.ID == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		var result any
		switch req.Method {
		case "initialize":
			result = map[string]any{"protocolVersion": "2025-11-25", "serverInfo": map[string]any{"name": "open", "version": "1"}}
		case "tools/list":
			result = map[string]any{"tools": []any{map[string]any{"name": "read", "annotations": map[string]any{"readOnlyHint": true}}}}
		default:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": *req.ID, "error": map[string]any{"code": -32601, "message": "no"}})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": *req.ID, "result": result})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// stubChecker stands in for the engine so the command's wiring is tested
// without a full run; the engine path is tested in internal/discover.
func stubChecker(t *testing.T) {
	t.Helper()
	orig := discoverChecker
	discoverChecker = func(float64, int) discover.Checker {
		return func(_ context.Context, endpoint string) (*report.Report, error) {
			return &report.Report{
				Passmcp: report.Meta{Version: "test", SchemaVersion: report.SchemaVersion},
				Target:  report.Target{Endpoint: endpoint, Scheme: "http", Transport: "http"},
				Started: time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC),
				Score:   report.Score{Total: 50, Grade: "D"},
				Counts:  report.Counts{Fail: 1},
				Phases: []probe.PhaseResult{{Name: "auth", Findings: []probe.Finding{
					{ID: "auth.unauthenticated_tools", Status: probe.Fail, Severity: probe.Critical},
				}}},
			}, nil
		}
	}
	t.Cleanup(func() { discoverChecker = orig })
}

// catchExit records osExit's code for the test.
func catchExit(t *testing.T) *int {
	t.Helper()
	code := -1
	orig := osExit
	osExit = func(c int) { code = c }
	t.Cleanup(func() { osExit = orig })
	return &code
}

// AC: DISC-06, DISC-07
func TestDiscoverCommandGatesAndWritesEveryOutput(t *testing.T) {
	srv := openMCP(t)
	stubChecker(t)
	code := catchExit(t)
	dir := t.TempDir()
	targets := filepath.Join(dir, "targets.txt")
	_ = os.WriteFile(targets, []byte(srv.URL+"\n"), 0o600)
	out := filepath.Join(dir, "out")
	gdir := filepath.Join(dir, "graph")
	state := filepath.Join(dir, "state.json")

	var stdout bytes.Buffer
	o := discoverFlags{targets: []string{targets}, output: "sarif", rps: 0, concurrency: 2, timeout: 5 * time.Second,
		validate: true, reportDir: out, graphDir: gdir, statePath: state}
	if err := runDiscover(context.Background(), &stdout, o); err != nil {
		t.Fatal(err)
	}
	if *code != 2 {
		t.Errorf("an exposed endpoint exited %d, want 2 so CI fails", *code)
	}
	if !strings.Contains(stdout.String(), `"version": "2.1.0"`) || !strings.Contains(stdout.String(), discover.RuleExposed) {
		t.Errorf("stdout is not the SARIF report:\n%s", stdout.String())
	}
	for _, f := range []string{"discovery.json", "discovery.sarif", "telemetry.ndjson"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("%s not written: %v", f, err)
		}
	}
	atts, _ := filepath.Glob(filepath.Join(out, "attestations", "*.json"))
	if len(atts) != 1 {
		t.Errorf("attestations written: %v", atts)
	}
	g, err := graph.Load(gdir)
	if err != nil || len(g.EdgesFrom(graph.ServerID("http", srv.URL+"/mcp"), graph.AttestedBy)) != 1 {
		t.Errorf("the graph does not link the server to its attestation: %v", err)
	}
	if _, err := os.Stat(state); err != nil {
		t.Errorf("state not written: %v", err)
	}

	// A second run in JSON with the same state sees the endpoint again.
	stdout.Reset()
	o.output, o.validate, o.graphDir, o.reportDir = "json", false, "", ""
	if err := runDiscover(context.Background(), &stdout, o); err != nil {
		t.Fatal(err)
	}
	var res discover.Result
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil || len(res.Endpoints) != 1 || res.Endpoints[0].Status != discover.StatusSeen {
		t.Fatalf("second run: %v %+v", err, res.Endpoints)
	}
}

// AC: DISC-04
func TestDiscoverCommandReadsEverySource(t *testing.T) {
	srv := openMCP(t)
	catchExit(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "claude.json")
	_ = os.WriteFile(cfg, []byte(`{"mcpServers": {"open": {"url": "`+srv.URL+`/mcp"}}}`), 0o600)
	gw := filepath.Join(dir, "gw.yaml")
	_ = os.WriteFile(gw, []byte("targets:\n- host: "+srv.URL+"/mcp\n"), 0o600)
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"servers": []any{
			map[string]any{"server": map[string]any{"name": "io.github.acme/open", "remotes": []any{map[string]any{"url": srv.URL + "/mcp"}}}},
		}, "metadata": map[string]any{}})
	}))
	defer reg.Close()

	var stdout bytes.Buffer
	o := discoverFlags{configs: []string{cfg}, gateways: []string{gw}, registries: []string{"io.github.acme"},
		registryURL: reg.URL, output: "json", concurrency: 1, timeout: 5 * time.Second}
	if err := runDiscover(context.Background(), &stdout, o); err != nil {
		t.Fatal(err)
	}
	var res discover.Result
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil || len(res.Endpoints) != 1 {
		t.Fatalf("%v %s", err, stdout.String())
	}
	types := map[string]bool{}
	for _, s := range res.Endpoints[0].Sources {
		types[s.Type] = true
	}
	if !types[discover.SourceConfig] || !types[discover.SourceGateway] || !types[discover.SourceRegistry] {
		t.Errorf("the endpoint's sources %+v do not name all three", res.Endpoints[0].Sources)
	}
}

func TestDiscoverCommandRefusesWhatCannotWork(t *testing.T) {
	catchExit(t)
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte("{"), 0o600)
	targets := filepath.Join(dir, "t.txt")
	_ = os.WriteFile(targets, []byte("10.0.0.0/8\n"), 0o600)
	base := discoverFlags{output: "text", concurrency: 1, timeout: time.Second}
	cases := map[string]discoverFlags{
		"output":      {output: "xml", concurrency: 1},
		"concurrency": {output: "text"},
		"no targets":  base,
		"missing":     withTargets(base, filepath.Join(dir, "absent")),
		"range":       withTargets(base, targets),
		"config":      withConfig(base, bad),
		"gateway":     withGateway(base, filepath.Join(dir, "absent")),
		"registry":    withRegistry(base, "io"),
	}
	for name, o := range cases {
		if err := runDiscover(context.Background(), io.Discard, o); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	srv := openMCP(t)
	st := filepath.Join(dir, "state.json")
	_ = os.WriteFile(st, []byte("{"), 0o600)
	good := filepath.Join(dir, "good.txt")
	_ = os.WriteFile(good, []byte(srv.URL+"\n"), 0o600)
	o := withTargets(base, good)
	o.statePath = st
	if err := runDiscover(context.Background(), io.Discard, o); err == nil {
		t.Error("a malformed state file gave no error")
	}
	var text bytes.Buffer
	o.statePath = ""
	if err := runDiscover(context.Background(), &text, o); err != nil || !strings.Contains(text.String(), "critical: exposed without authentication") {
		t.Errorf("text output: %v\n%s", err, text.String())
	}
}

func withTargets(o discoverFlags, p string) discoverFlags   { o.targets = []string{p}; return o }
func withConfig(o discoverFlags, p string) discoverFlags    { o.configs = []string{p}; return o }
func withGateway(o discoverFlags, p string) discoverFlags   { o.gateways = []string{p}; return o }
func withRegistry(o discoverFlags, ns string) discoverFlags { o.registries = []string{ns}; return o }
