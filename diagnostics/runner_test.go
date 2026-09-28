// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package diagnostics_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp"
	"satellion.com/passmcp/diagnostics"
	"satellion.com/passmcp/trace"
)

func fakeMCP(t *testing.T, calls map[string]int, traceIDs *[]string) *httptest.Server {
	t.Helper()
	yes := true
	tools := []passmcp.Tool{
		{Name: "get_time", InputSchema: json.RawMessage(`{"type":"object"}`), OutputSchema: json.RawMessage(`{"type":"object","required":["iso"],"properties":{"iso":{"type":"string"}}}`), Annotations: &passmcp.ToolAnnotations{ReadOnlyHint: &yes}},
		{Name: "search", InputSchema: json.RawMessage(`{"type":"object","required":["q"],"properties":{"q":{"type":"string"}}}`), OutputSchema: json.RawMessage(`{"type":"object","required":["hits"],"properties":{"hits":{"type":"array"}}}`), Annotations: &passmcp.ToolAnnotations{ReadOnlyHint: &yes}},
		{Name: "slow", InputSchema: json.RawMessage(`{"type":"object"}`), Annotations: &passmcp.ToolAnnotations{ReadOnlyHint: &yes}},
		{Name: "broken", InputSchema: json.RawMessage(`{"type":"object"}`), Annotations: &passmcp.ToolAnnotations{ReadOnlyHint: &yes}},
		{Name: "delete_all", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*traceIDs = append(*traceIDs, r.Header.Get(trace.Header))
		var req struct {
			ID     *int64          `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		reply := func(v any) {
			b, _ := json.Marshal(v)
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":%s}`, *req.ID, b)
		}
		switch req.Method {
		case "initialize":
			reply(map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "serverInfo": map[string]any{"name": "fake", "version": "1"}})
		case "notifications/initialized":
			w.WriteHeader(202)
		case "tools/list":
			reply(map[string]any{"tools": tools})
		case "tools/call":
			var p struct {
				Name string         `json:"name"`
				Args map[string]any `json:"arguments"`
			}
			json.Unmarshal(req.Params, &p)
			calls[p.Name]++
			switch p.Name {
			case "get_time":
				reply(passmcp.CallToolResult{Content: []passmcp.Content{{Type: "text", Text: "now"}}, StructuredContent: json.RawMessage(`{"iso":"2026-01-01T00:00:00Z"}`)})
			case "search":
				if _, ok := p.Args["q"]; !ok {
					reply(passmcp.CallToolResult{IsError: true, Content: []passmcp.Content{{Type: "text", Text: "missing q"}}})
					return
				}
				reply(passmcp.CallToolResult{Content: []passmcp.Content{{Type: "text", Text: "ok"}}, StructuredContent: json.RawMessage(`{"hits":"not-an-array"}`)})
			case "slow":
				// A second, not the 120ms this used to be.
				//
				// The assertion downstream is that `slow` is reported as a
				// latency outlier, and an outlier is defined relatively: at
				// least OutlierFactor times the median. The other three tools
				// reply immediately, so on an idle machine 120ms was a wide
				// margin over a near-zero median.
				//
				// Under load it is not. Running the whole module's tests with
				// -race saturates the machine, the three "immediate" calls
				// take 80ms of scheduler noise each, and the recorded failure
				// was exactly that:
				//
				//	outliers = [] (latency {Count:4 P50:81.572458ms
				//	                        P95:162.845667ms Max:162.845667ms})
				//
				// 162ms against a median of 81ms is not three times anything,
				// so the rule was right and the fixture was wrong. A second
				// gives the signal room to dominate the noise: even if the
				// fast calls take 300ms, the gap still clears the factor.
				//
				// The rule itself is unit-tested deterministically elsewhere;
				// what this test is for is that the runner plumbs a detected
				// outlier through to the report.
				time.Sleep(time.Second)
				reply(passmcp.CallToolResult{Content: []passmcp.Content{{Type: "text", Text: "zzz"}}})
			case "broken":
				w.WriteHeader(500)
			default:
				reply(passmcp.CallToolResult{Content: []passmcp.Content{{Type: "text", Text: "done"}}})
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRunnerEndToEnd(t *testing.T) {
	calls := map[string]int{}
	var traceIDs []string
	srv := fakeMCP(t, calls, &traceIDs)
	c, err := passmcp.New(passmcp.Config{Endpoint: srv.URL, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := trace.WithID(context.Background(), "run-123")
	if _, err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	// The production floor, not a lowered one. With a 50ms floor any call
	// that caught a scheduler hiccup qualified as an outlier: a run under
	// -race reported `broken took 112.9ms (p50 29.3ms)` alongside the
	// intended one. 500ms is high enough that noise cannot reach it and low
	// enough that the fixture's deliberate second clears it easily.
	r := diagnostics.NewRunner(diagnostics.Options{RequestsPerSecond: -1, OutlierFloor: 500 * time.Millisecond, OutlierFactor: 3})
	rep, err := r.Run(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if rep.TraceID != "run-123" {
		t.Errorf("trace id = %q", rep.TraceID)
	}
	for _, id := range traceIDs {
		if id != "run-123" {
			t.Fatalf("trace header not propagated: %v", traceIDs)
		}
	}
	if calls["delete_all"] != 0 {
		t.Fatal("destructive tool was invoked under default policy")
	}
	if rep.ToolsDiscovered != 5 || rep.ToolsExecuted != 4 || rep.ToolsSkipped != 1 {
		t.Errorf("counts: %+v", rep)
	}
	if rep.Successful != 3 || rep.ProtocolErrors != 1 || rep.ToolErrors != 0 {
		t.Errorf("outcomes: ok=%d proto=%d tool=%d", rep.Successful, rep.ProtocolErrors, rep.ToolErrors)
	}
	if len(rep.SchemaMismatches) != 1 || !strings.HasPrefix(rep.SchemaMismatches[0], "search:") {
		t.Errorf("schema mismatches = %v", rep.SchemaMismatches)
	}
	// That `slow` is reported, not that it is the only one reported.
	//
	// An outlier is defined relative to the median, so on a loaded machine
	// any call can cross the factor and the count becomes a measurement of
	// the test runner rather than of the code under test. What this test is
	// for is that a detected outlier reaches the report, named. The rule
	// itself is unit-tested deterministically in diagnostics_test.go and
	// more_test.go.
	var sawSlow bool
	for _, o := range rep.Outliers {
		if strings.HasPrefix(o, "slow ") {
			sawSlow = true
		}
	}
	if !sawSlow {
		t.Errorf("the deliberately slow tool was not reported as an outlier: %v (latency %+v)",
			rep.Outliers, rep.Latency)
	}
	if len(rep.MissingSchemas) != 3 || len(rep.Unannotated) != 1 {
		t.Errorf("missing schemas = %v unannotated = %v", rep.MissingSchemas, rep.Unannotated)
	}
	if rep.Latency.Count != 4 || rep.Latency.Max < time.Second {
		t.Errorf("latency = %+v", rep.Latency)
	}
	// 100 - 12.5 (1/4 failed) - 5 (schema) - 1 (unannotated) - 3 (missing schemas) = 78.5
	if rep.QualityScore != 78.5 {
		t.Errorf("score = %v deductions = %v", rep.QualityScore, rep.Deductions)
	}
	if _, err := json.Marshal(rep); err != nil {
		t.Errorf("report must serialise: %v", err)
	}
}

func TestRunnerAllowDestructiveOptIn(t *testing.T) {
	calls := map[string]int{}
	var ids []string
	srv := fakeMCP(t, calls, &ids)
	c, _ := passmcp.New(passmcp.Config{Endpoint: srv.URL, HTTPClient: srv.Client()})
	if _, err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := diagnostics.NewRunner(diagnostics.Options{RequestsPerSecond: -1, Policy: diagnostics.Policy{AllowDestructive: true, Only: []string{"delete_all"}}})
	rep, err := r.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if calls["delete_all"] != 1 || rep.ToolsExecuted != 1 || rep.ToolsSkipped != 4 {
		t.Errorf("calls = %v report = %+v", calls, rep)
	}
}
