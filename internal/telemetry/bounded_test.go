// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package telemetry

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestRecorderIsBounded: the recording was an append-only slice holding
// every exchange with its headers and up to BodyCap of its body. A run
// against a large catalog had no ceiling on it.
func TestRecorderIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	rec := New()
	rec.MaxEvents = 10
	hc := &http.Client{Transport: rec.Wrap(srv.Client().Transport)}
	const total = 60
	for i := 0; i < total; i++ {
		resp, err := hc.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	if got := len(rec.Events()); got > 10 {
		t.Errorf("retained %d events, cap is 10", got)
	}
	if got := rec.Dropped(); got != total-10 {
		t.Errorf("dropped = %d, want %d", got, total-10)
	}
	// The summary must still describe the whole run, not only what is left.
	s := rec.Summary()
	if s.Requests != total {
		t.Errorf("summary counted %d of %d requests", s.Requests, total)
	}
	if s.ByStatus["2xx"] != total {
		t.Errorf("by-status lost the dropped events: %v", s.ByStatus)
	}
	// Count is monotonic so evidence ranges on findings stay meaningful.
	if rec.Count() != total {
		t.Errorf("Count = %d, want %d", rec.Count(), total)
	}
}

func TestRecorderUnboundedWhenNegative(t *testing.T) {
	rec := New()
	rec.MaxEvents = -1
	for i := 0; i < 50; i++ {
		rec.add(Event{Method: "GET", URL: "https://x/"})
	}
	if len(rec.Events()) != 50 {
		t.Errorf("a negative MaxEvents means unbounded, got %d", len(rec.Events()))
	}
	if rec.Dropped() != 0 {
		t.Error("nothing should have been dropped")
	}
}

// slowReader hands back a few bytes at a time so a concurrent Close lands
// in the middle of a Read rather than after it.
type slowReader struct{ r io.Reader }

func (s slowReader) Read(p []byte) (int, error) {
	if len(p) > 8 {
		p = p[:8]
	}
	return s.r.Read(p)
}

func (s slowReader) Close() error { return nil }

// TestBodyRecorderConcurrentReadClose is the regression for a data race:
// Read mutated the byte count and the capture buffer outside the mutex that
// finish holds, so a Close arriving mid-Read raced both.
//
// http.Response.Body is documented as not safe for concurrent use, so this
// is defensive rather than a bug net/http will trigger on its own — but the
// recorder wraps every body passmcp reads, including ones a cancelled run
// abandons, and a wrapper that corrupts its own counters under a caller's
// mistake is not worth the debugging it costs. Run under -race.
func TestBodyRecorderConcurrentReadClose(t *testing.T) {
	for i := 0; i < 50; i++ {
		rec := New()
		rec.CaptureBodies = true
		ev := &Event{}
		var mu sync.Mutex
		br := &bodyRecorder{
			rc:  slowReader{strings.NewReader(strings.Repeat("a", 1<<16))},
			rec: rec, ev: ev, mu: &mu,
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = io.Copy(io.Discard, br) }()
		go func() { defer wg.Done(); _ = br.Close() }()
		wg.Wait()
	}
}

// The capture buffer must not overshoot its cap by a whole read.
func TestBodyCapIsEnforced(t *testing.T) {
	big := strings.Repeat("b", 512<<10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(big))
	}))
	defer srv.Close()

	rec := New()
	rec.CaptureBodies = true
	rec.BodyCap = 1024
	hc := &http.Client{Transport: rec.Wrap(srv.Client().Transport)}
	resp, err := hc.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	ev := rec.Events()[0]
	if ev.ResponseBytes != int64(len(big)) {
		t.Errorf("byte count must be the true size: %d", ev.ResponseBytes)
	}
	if !strings.Contains(ev.ResponseBody, "truncated") {
		t.Errorf("a capped body must say so: %q", ev.ResponseBody[:min(80, len(ev.ResponseBody))])
	}
	// The retained text is the cap plus the truncation note, not the body.
	if len(ev.ResponseBody) > rec.BodyCap+128 {
		t.Errorf("retained %d bytes for a cap of %d", len(ev.ResponseBody), rec.BodyCap)
	}
}

// A token in a body too large to parse must still be masked.
func TestTruncatedJSONStillRedacts(t *testing.T) {
	r := &Redactor{}
	body := `{"padding":"` + strings.Repeat("x", 200) + `","access_token":"super-secret-value","refresh_token":"another-secret"`
	out := r.JSONOrKeys([]byte(body))
	if strings.Contains(out, "super-secret-value") || strings.Contains(out, "another-secret") {
		t.Fatalf("a truncated body leaked its tokens: %s", out)
	}
	if !strings.Contains(out, Mask) {
		t.Errorf("nothing was masked: %s", out)
	}
	// Having seen them once, the redactor masks them everywhere after.
	if got := r.String("log line with super-secret-value in it"); strings.Contains(got, "super-secret-value") {
		t.Errorf("the secret was not registered: %s", got)
	}
	// Valid JSON still takes the parsing path.
	if out := r.JSONOrKeys([]byte(`{"access_token":"abcd1234"}`)); strings.Contains(out, "abcd1234") {
		t.Errorf("valid JSON leaked: %s", out)
	}
}
