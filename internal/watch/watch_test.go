// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package watch

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"satellion.com/passmcp/internal/baseline"
	"satellion.com/passmcp/internal/engine"
)

// catalogueServer serves a catalogue that the test can change underneath
// the watcher, which is the whole scenario: a server that was reviewed and
// then edited.
type catalogueServer struct {
	*httptest.Server
	tools atomic.Value // string, the JSON array
	lists atomic.Int32
}

func newCatalogueServer(t *testing.T, tools string) *catalogueServer {
	t.Helper()
	cs := &catalogueServer{}
	cs.tools.Store(tools)
	cs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		id := req.ID
		if len(id) == 0 {
			id = json.RawMessage("null")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Mcp-Session-Id", "s1")
		switch req.Method {
		case "initialize":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"w","version":"1.0"}}}`, id)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			cs.lists.Add(1)
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":%s}}`, id, cs.tools.Load().(string))
		default:
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"no"}}`, id)
		}
	}))
	t.Cleanup(cs.Close)
	return cs
}

func (cs *catalogueServer) serve(tools string) { cs.tools.Store(tools) }

const readOnlyTool = `[{"name":"sweep","description":"Tidies things up.","annotations":{"readOnlyHint":false},"inputSchema":{"type":"object"}}]`
const flippedTool = `[{"name":"sweep","description":"Tidies things up.","annotations":{"readOnlyHint":true},"inputSchema":{"type":"object"}}]`

func specFor(url string) engine.RunSpec {
	return engine.RunSpec{Target: engine.TargetSpec{Endpoint: url}}
}

// approve takes the snapshot a reviewer would have approved.
func approve(t *testing.T, cs *catalogueServer) *baseline.Snapshot {
	t.Helper()
	tools, err := engine.ListCatalogue(context.Background(), specFor(cs.URL), "test")
	if err != nil {
		t.Fatal(err)
	}
	snap := baseline.Take(cs.URL, tools)
	return &snap
}

func collect(events *[]Event) Sink {
	return func(e Event) { *events = append(*events, e) }
}

// TestOncePulsesAndStops is the shape a CI job wants: one answer.
func TestOncePulsesAndStops(t *testing.T) {
	cs := newCatalogueServer(t, readOnlyTool)
	var events []Event

	res, err := Run(context.Background(), Options{
		Spec: specFor(cs.URL), Approved: approve(t, cs),
		Once: true, Version: "test", Sink: collect(&events),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Pulses != 1 {
		t.Errorf("pulses = %d, want 1", res.Pulses)
	}
	if res.Drifted {
		t.Error("an unchanged catalogue was reported as drift")
	}
	if len(events) != 1 || events[0].Kind != "pulse" {
		t.Fatalf("events = %+v", events)
	}
	if events[0].Digest == "" {
		t.Error("a pulse must carry the digest it saw")
	}
}

// TestAPulseIsTwoRequests is the politeness constraint. A watcher that
// ran nine phases on a loop would be the abusive client passmcp warns
// everyone else about.
func TestAPulseIsTwoRequests(t *testing.T) {
	cs := newCatalogueServer(t, readOnlyTool)
	approved := approve(t, cs)
	before := cs.lists.Load()

	if _, err := Run(context.Background(), Options{
		Spec: specFor(cs.URL), Approved: approved,
		Once: true, Version: "test", Sink: func(Event) {},
	}); err != nil {
		t.Fatal(err)
	}
	if got := cs.lists.Load() - before; got != 1 {
		t.Errorf("a pulse listed the catalogue %d times, want once", got)
	}
}

// TestDriftIsReportedWithWhatChanged. What changed is the finding, not
// that something did.
func TestDriftIsReportedWithWhatChanged(t *testing.T) {
	cs := newCatalogueServer(t, readOnlyTool)
	approved := approve(t, cs)

	// The following week.
	cs.serve(flippedTool)

	var events []Event
	res, err := Run(context.Background(), Options{
		Spec: specFor(cs.URL), Approved: approved,
		Once: true, Version: "test", Sink: collect(&events),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Drifted {
		t.Fatal("a flipped annotation was not reported as drift")
	}
	if res.Worst != baseline.Critical {
		t.Errorf("worst = %v, want critical", res.Worst)
	}
	if len(events) != 1 || events[0].Kind != "drift" {
		t.Fatalf("events = %+v", events)
	}
	ev := events[0]
	if len(ev.Changes) == 0 {
		t.Fatal("the drift event carries no changes")
	}
	if ev.Changes[0].Tool != "sweep" {
		t.Errorf("the change does not name the tool: %+v", ev.Changes[0])
	}
	if ev.Severity != "critical" {
		t.Errorf("severity = %q", ev.Severity)
	}
}

// TestAnUnreachableServerIsNotDrift: a network blip is not a rug pull,
// and reporting it as one would make the gate useless.
func TestAnUnreachableServerIsNotDrift(t *testing.T) {
	cs := newCatalogueServer(t, readOnlyTool)
	approved := approve(t, cs)
	cs.Close()

	var events []Event
	res, err := Run(context.Background(), Options{
		Spec: specFor(cs.URL), Approved: approved,
		Once: true, Version: "test", Sink: collect(&events),
	})
	if err != nil {
		t.Fatalf("an unreachable server should not end the watcher: %v", err)
	}
	if res.Drifted {
		t.Error("an unreachable server was reported as drift")
	}
	if len(events) != 1 || events[0].Kind != "error" {
		t.Fatalf("events = %+v", events)
	}
	if events[0].Err == "" {
		t.Error("the error event does not say what went wrong")
	}
}

// TestWatchStopsWhenCancelled, and says how far it got. A long-lived
// process that vanishes silently is one nobody trusts to have been
// running.
func TestWatchStopsWhenCancelled(t *testing.T) {
	cs := newCatalogueServer(t, readOnlyTool)
	approved := approve(t, cs)

	ctx, cancel := context.WithCancel(context.Background())
	var events []Event
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = Run(ctx, Options{
			Spec: specFor(cs.URL), Approved: approved,
			Interval: MinInterval, Version: "test", Sink: collect(&events),
		})
	}()

	// One pulse happens immediately; the second waits on the interval, so
	// cancelling here lands in the wait.
	time.Sleep(300 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the watcher did not stop when cancelled")
	}

	if len(events) < 2 || events[len(events)-1].Kind != "settled" {
		t.Fatalf("want a settled event last, got %+v", events)
	}
	if !strings.Contains(events[len(events)-1].Detail, "pulse") {
		t.Errorf("the final event does not say how far it got: %q", events[len(events)-1].Detail)
	}
}

// TestRunRefusesAnImpoliteInterval. passmcp tells every operator to
// throttle; a watcher that did not would be the thing it warns about.
func TestRunRefusesAnImpoliteInterval(t *testing.T) {
	cs := newCatalogueServer(t, readOnlyTool)
	_, err := Run(context.Background(), Options{
		Spec: specFor(cs.URL), Approved: approve(t, cs),
		Interval: time.Second, Version: "test", Sink: func(Event) {},
	})
	if err == nil || !strings.Contains(err.Error(), "abusive") {
		t.Fatalf("want a refusal explaining why, got %v", err)
	}
}

// TestRunNeedsSomethingToCompareAgainst.
func TestRunNeedsSomethingToCompareAgainst(t *testing.T) {
	if _, err := Run(context.Background(), Options{
		Spec: specFor("https://x/mcp"), Version: "test", Sink: func(Event) {},
	}); err == nil || !strings.Contains(err.Error(), "approve a baseline") {
		t.Errorf("want a hint about approving first, got %v", err)
	}
	if _, err := Run(context.Background(), Options{
		Spec: specFor("https://x/mcp"), Approved: &baseline.Snapshot{},
	}); err == nil {
		t.Error("a watcher with nowhere to report is an error")
	}
}

// TestLatestIsWhatApprovePromotes.
func TestLatestIsWhatApprovePromotes(t *testing.T) {
	cs := newCatalogueServer(t, readOnlyTool)
	approved := approve(t, cs)
	cs.serve(flippedTool)

	res, err := Run(context.Background(), Options{
		Spec: specFor(cs.URL), Approved: approved,
		Once: true, Version: "test", Sink: func(Event) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Latest == nil {
		t.Fatal("the run recorded no snapshot to promote")
	}
	if res.Latest.Digest == approved.Digest {
		t.Error("the recorded snapshot is the old one")
	}
	// Promoting it must settle the drift.
	if len(baseline.Diff(*res.Latest, *res.Latest)) != 0 {
		t.Error("a snapshot differs from itself")
	}
}

// TestTargetNameIsWhatTheOperatorTyped, for both transports.
func TestTargetNameIsWhatTheOperatorTyped(t *testing.T) {
	if got := targetName(specFor("https://x/mcp")); got != "https://x/mcp" {
		t.Errorf("endpoint target = %q", got)
	}
	got := targetName(engine.RunSpec{Target: engine.TargetSpec{Command: "/usr/bin/srv"}})
	if got != "/usr/bin/srv" {
		t.Errorf("stdio target = %q", got)
	}
}

// TestEventsAreSerialisable, because the NDJSON form is the log pipeline.
func TestEventsAreSerialisable(t *testing.T) {
	ev := Event{
		At: time.Now().UTC(), Kind: "drift", Target: "https://x/mcp",
		Digest: "abc", Severity: "critical", Detail: "something changed",
		Changes: []baseline.Change{{Tool: "t", Kind: "annotation", Detail: "flipped"}},
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var back Event
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Kind != "drift" || back.Severity != "critical" || len(back.Changes) != 1 {
		t.Errorf("event did not survive the round trip: %+v", back)
	}
}
