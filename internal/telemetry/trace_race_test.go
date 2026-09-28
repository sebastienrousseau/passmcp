// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package telemetry

import (
	"errors"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"testing"
)

// httptrace callbacks are not guaranteed to have stopped when RoundTrip
// returns. net/http dials in a background goroutine — startDialConnForLocked
// — and that goroutine fires ConnectStart and ConnectDone against the same
// ClientTrace even when the request it was started for has already failed.
//
// The recorder's error path used to release its mutex and then pass the
// event to add by value, which copies every field. A late ConnectDone
// writing Timings.Connect under the mutex therefore raced a read that was
// not holding it. CI caught it on a shuffled race run; it had never run
// before, because the race job could not build without cgo.
//
// lateTraceTransport models the transport's behaviour directly rather than
// waiting for the real one to interleave badly: it fires the callbacks from
// another goroutine and fails the request, which is exactly the window.
type lateTraceTransport struct {
	started chan struct{}
	stop    *atomic.Bool
	wg      *sync.WaitGroup
}

func (l *lateTraceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ct := httptrace.ContextClientTrace(req.Context())
	if ct == nil {
		return nil, errors.New("no client trace on the request")
	}
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		close(l.started)
		// Keep firing until the test says stop, so the callbacks are
		// certainly still running while the recorder handles the failure.
		// A fixed number of iterations can finish first, and then the
		// window this exists to cover is never opened.
		for !l.stop.Load() {
			ct.ConnectStart("tcp", "127.0.0.1:1")
			ct.ConnectDone("tcp", "127.0.0.1:1", errors.New("dial failed"))
		}
	}()
	<-l.started
	return nil, errors.New("request failed")
}

func TestTraceCallbacksMayOutliveRoundTrip(t *testing.T) {
	var wg sync.WaitGroup
	var stop atomic.Bool
	rec := New()
	base := &lateTraceTransport{started: make(chan struct{}), stop: &stop, wg: &wg}
	rt := rec.Wrap(base)

	req, err := http.NewRequest(http.MethodGet, "https://example.invalid/mcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, rtErr := rt.RoundTrip(req)
	stop.Store(true)
	wg.Wait()
	if rtErr == nil {
		t.Fatal("the transport was supposed to fail the request")
	}

	// The failure is still recorded; the point is that recording it does
	// not read the event while a trace callback is still writing to it.
	if got := rec.Count(); got != 1 {
		t.Errorf("a failed request should still be recorded, got %d events", got)
	}
}
