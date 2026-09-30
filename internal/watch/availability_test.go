// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package watch

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// knobbedServer is catalogueServer with the failure modes an availability
// figure has to tell apart: an HTTP status for every request, a JSON-RPC
// error from tools/list, and a listing that never answers. It also keeps
// a clock that moves only while it serves, by as long as the initialize
// and tools/list knobs say, so a latency can be asserted exactly.
type knobbedServer struct {
	*catalogueServer
	status    atomic.Int32
	listErr   atomic.Bool
	hang      atomic.Bool
	clock     steppedClock
	initTakes atomic.Int64 // nanoseconds the clock moves per initialize
	listTakes atomic.Int64 // nanoseconds the clock moves per tools/list
}

// steppedClock is a clock that stands still until advanced. Standing
// still is what a coarse clock does for any pulse shorter than its tick.
type steppedClock struct{ ns atomic.Int64 }

func (c *steppedClock) now() time.Time { return time.Unix(0, c.ns.Load()) }

// took advances the clock as the method named in body would take.
func (ks *knobbedServer) took(body string) {
	switch {
	case strings.Contains(body, `"initialize"`):
		ks.clock.ns.Add(ks.initTakes.Load())
	case strings.Contains(body, `"tools/list"`):
		ks.clock.ns.Add(ks.listTakes.Load())
	}
}

func newKnobbedServer(t *testing.T) *knobbedServer {
	t.Helper()
	ks := &knobbedServer{catalogueServer: newCatalogueServer(t, readOnlyTool)}
	inner := ks.Config.Handler
	ks.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s := ks.status.Load(); s != 0 {
			w.WriteHeader(int(s))
			return
		}
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		ks.took(string(body))
		if strings.Contains(string(body), `"tools/list"`) {
			if ks.hang.Load() {
				<-r.Context().Done()
				return
			}
			if ks.listErr.Load() {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"jsonrpc":"2.0","id":2,"error":{"code":-32603,"message":"catalogue unavailable"}}`)
				return
			}
		}
		inner.ServeHTTP(w, r)
	})
	return ks
}

// TestAPulseRecordsLatencyAndStatus: every pulse says how long it took and
// how it went, which is what the availability figure is made of. The
// latency is asserted exactly, on a clock the server moves, because a real
// one cannot be relied on to move at all: a loopback pulse takes a few
// milliseconds, inside one tick of Windows' 15.6 ms clock.
func TestAPulseRecordsLatencyAndStatus(t *testing.T) {
	ks := newKnobbedServer(t)
	approved := approve(t, ks.catalogueServer)
	ks.initTakes.Store(int64(5 * time.Millisecond))
	ks.listTakes.Store(int64(20 * time.Millisecond))
	var events []Event
	res, err := Run(context.Background(), Options{
		Spec: specFor(ks.URL), Approved: approved,
		Once: true, Version: "test", Sink: collect(&events),
		clock: ks.clock.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Connect to listing: the handshake and the listing are both inside
	// the timed window.
	ev := events[0]
	if got := [2]string{ev.Status, ev.ErrorKind}; got != [2]string{"ok", ""} || ev.LatencyMS != 25 {
		t.Errorf("status/kind = %v latency_ms = %v, want [ok ] 25", got, ev.LatencyMS)
	}
	sum := res.Summary
	if got := [3]int{sum.Pulses, sum.OK, sum.Latency.Samples}; got != [3]int{1, 1, 1} || sum.SuccessRate != 1 || sum.Latency.P50 != 25 {
		t.Errorf("summary = %+v", sum)
	}
	if res.Target != ks.URL {
		t.Errorf("result target = %q", res.Target)
	}
}

// TestAPulseInsideOneTickMeasuresZero is the Windows case: a clock that
// did not move reports zero rather than a floor or a guess, and the
// pulse still counts as answered. A latency is a measurement, and one
// the clock could not make is not made up.
func TestAPulseInsideOneTickMeasuresZero(t *testing.T) {
	ks := newKnobbedServer(t)
	var events []Event
	res, err := Run(context.Background(), Options{
		Spec: specFor(ks.URL), Approved: approve(t, ks.catalogueServer),
		Once: true, Version: "test", Sink: collect(&events),
		clock: ks.clock.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev := events[0]; ev.Status != "ok" || ev.LatencyMS != 0 {
		t.Errorf("status = %q latency_ms = %v, want ok 0", ev.Status, ev.LatencyMS)
	}
	if sum := res.Summary; sum.OK != 1 || sum.Latency.Samples != 1 || sum.Latency.P50 != 0 {
		t.Errorf("summary = %+v", sum)
	}
}

// failedPulse is one way a pulse can fail, and how it must be classed.
type failedPulse struct {
	name   string
	set    func(*knobbedServer)
	status Status
	kind   string
}

// runFailedPulse takes one pulse against a server broken the way fp says.
func runFailedPulse(t *testing.T, fp failedPulse) (Event, *Result) {
	t.Helper()
	ks := newKnobbedServer(t)
	approved := approve(t, ks.catalogueServer)
	fp.set(ks)
	var events []Event
	res, err := Run(context.Background(), Options{
		Spec: specFor(ks.URL), Approved: approved,
		Once: true, Version: "test", Sink: collect(&events),
	})
	if err != nil {
		t.Fatal(err)
	}
	return events[0], res
}

// TestFailedPulsesAreClassified, one per class a pulse can actually hit.
func TestFailedPulsesAreClassified(t *testing.T) {
	cases := []failedPulse{
		{"unreachable", func(ks *knobbedServer) { ks.Close() }, StatusTransport, "connection_refused"},
		{"server error", func(ks *knobbedServer) { ks.status.Store(503) }, StatusTransport, "http_503"},
		// The kind depends on how the client meets a bare 401 (a login
		// it cannot perform, or the status itself); the class does not.
		{"unauthorised", func(ks *knobbedServer) { ks.status.Store(401) }, StatusAuth, ""},
		{"rpc error", func(ks *knobbedServer) { ks.listErr.Store(true) }, StatusProtocol, "jsonrpc_-32603"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, res := runFailedPulse(t, c)
			assertFailedPulse(t, c, ev, res)
		})
	}
}

// assertFailedPulse checks the event and summary of one failed pulse.
func assertFailedPulse(t *testing.T, c failedPulse, ev Event, res *Result) {
	t.Helper()
	if ev.Kind != "error" || ev.Status != string(c.status) || ev.ErrorKind == "" {
		t.Fatalf("event = %+v, want an error of class %s with a kind", ev, c.status)
	}
	if c.kind != "" && ev.ErrorKind != c.kind {
		t.Errorf("error_kind = %q, want %q (%s)", ev.ErrorKind, c.kind, ev.Err)
	}
	sum := res.Summary
	got := [3]int{sum.Failed, sum.WorstFailureStreak, sum.ByStatus[string(c.status)]}
	if got != [3]int{1, 1, 1} || sum.SuccessRate != 0 {
		t.Errorf("summary = %+v", sum)
	}
}

// TestAnInterruptedPulseIsNotAnOutage. Ctrl-C during a slow listing is
// the operator leaving, not the server failing, and counting it would put
// a failure in every summary of a watcher somebody stopped.
func TestAnInterruptedPulseIsNotAnOutage(t *testing.T) {
	ks := newKnobbedServer(t)
	approved := approve(t, ks.catalogueServer)
	ks.hang.Store(true)

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	var events []Event
	res, err := Run(ctx, Options{
		Spec: specFor(ks.URL), Approved: approved,
		Interval: MinInterval, Version: "test", Sink: collect(&events),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range events {
		if ev.Kind == "error" {
			t.Errorf("an interrupted pulse was reported as an error: %+v", ev)
		}
	}
	if len(events) == 0 || events[len(events)-1].Kind != "settled" {
		t.Fatalf("want a settled event last, got %+v", events)
	}
	if res.Summary.Pulses != 0 || res.Summary.Failed != 0 {
		t.Errorf("summary = %+v, want nothing counted", res.Summary)
	}
}

// TestTheSummaryEventClosesTheStream: what a log pipeline keys on at the
// end of a run.
func TestTheSummaryEventClosesTheStream(t *testing.T) {
	cs := newCatalogueServer(t, readOnlyTool)
	res, err := Run(context.Background(), Options{
		Spec: specFor(cs.URL), Approved: approve(t, cs),
		Once: true, Version: "test", Sink: func(Event) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	ev := res.SummaryEvent(at)
	if ev.Kind != "summary" || ev.Summary == nil || ev.Summary.Pulses != 1 || ev.Target != cs.URL || !ev.At.Equal(at) {
		t.Fatalf("summary event = %+v", ev)
	}
	if !strings.Contains(ev.Detail, "1 of 1") {
		t.Errorf("detail = %q", ev.Detail)
	}
}
