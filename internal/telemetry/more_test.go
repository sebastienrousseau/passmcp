// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package telemetry

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCaptureTruncationAndSSEError(t *testing.T) {
	big := strings.Repeat("a", 100)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sse" {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-5,\"message\":\"m\"}}\n\n"))
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(big))
	}))
	defer srv.Close()
	rec := New()
	rec.CaptureBodies = true
	rec.BodyCap = 10
	hc := &http.Client{Transport: rec.Wrap(srv.Client().Transport)}
	resp, err := hc.Post(srv.URL, "text/plain", strings.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = new(bytes.Buffer).ReadFrom(resp.Body)
	_ = resp.Body.Close()
	resp, _ = hc.Post(srv.URL+"/sse", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"m"}`))
	_, _ = new(bytes.Buffer).ReadFrom(resp.Body)
	_ = resp.Body.Close()
	evs := rec.Events()
	if len(evs) != 2 {
		t.Fatalf("events = %d", len(evs))
	}
	if !strings.Contains(evs[0].RequestBody, "truncated 90 bytes") || !strings.Contains(evs[0].ResponseBody, "truncated") {
		t.Errorf("truncation: %q %q", evs[0].RequestBody, evs[0].ResponseBody)
	}
	if evs[1].RPC == nil || evs[1].RPC.ErrorCode != -5 {
		t.Errorf("sse rpc error not parsed: %+v", evs[1].RPC)
	}
	if rec.Count() != 2 {
		t.Error("Count")
	}
	s := rec.Summary()
	if s.ByHost[strings.TrimPrefix(srv.URL, "http://")] != 2 {
		t.Errorf("summary = %+v", s)
	}
	// Wall is the span between the first and last event timestamp. Two
	// loopback requests can land inside one tick of the Windows system
	// clock, which makes a zero here a true measurement rather than a lost
	// one. Elsewhere the clock resolves it, and a zero would mean the
	// timestamps were never recorded.
	if runtime.GOOS != "windows" && s.Wall <= 0 {
		t.Errorf("wall time not measured: %+v", s)
	}
	// Sink receives events.
	n := 0
	rec.Sink = func(Event) { n++ }
	resp, _ = hc.Get(srv.URL)
	_ = resp.Body.Close()
	if n != 1 {
		t.Errorf("sink calls = %d", n)
	}
	// Empty capture.
	if rec.captureBody("application/json", nil, 0) != "" {
		t.Error("empty body capture")
	}
	if rec.captureBody("application/x-www-form-urlencoded", []byte("a=b"), 3) != "a=b" {
		t.Error("form capture")
	}
	// HAR with zero timings and an error event.
	rec2 := New()
	rec2.add(Event{Time: time.Now(), Method: "GET", URL: "http://x/", Error: "dial refused", Timings: Timings{TTFB: 5 * time.Millisecond, Total: 2 * time.Millisecond}})
	var buf bytes.Buffer
	if err := rec2.WriteHAR(&buf, "t"); err != nil || !strings.Contains(buf.String(), "dial refused") {
		t.Errorf("har: %v", err)
	}
	if rec2.Summary().ByStatus["error"] != 1 || rec2.Summary().Errors != 1 {
		t.Errorf("error summary: %+v", rec2.Summary())
	}
	if _, err := (Timings{}).MarshalJSON(); err != nil {
		t.Error(err)
	}
}

func TestRedactorMore(t *testing.T) {
	r := &Redactor{}
	if (*Redactor)(nil).String("x") != "x" {
		t.Error("nil redactor passthrough")
	}
	r.Add("dupsecret")
	r.Add("dupsecret")
	if len(r.secrets) != 1 {
		t.Error("duplicate secret added")
	}
	r.Add("with space")
	if got := r.String("q=with+space"); !strings.Contains(got, Mask) {
		t.Errorf("escaped form not masked: %q", got)
	}
	if got := r.URL("://bad url"); got == "" {
		t.Error("bad url falls back")
	}
	if got := r.Form("%zz"); got != "%zz" {
		t.Errorf("bad form falls back: %q", got)
	}
	out := r.JSON([]byte(`{"items":[{"access_token":"tok-secret"},"x"],"nested":{"password":"pw-secret"},"keep":1}`))
	if strings.Contains(out, "tok-secret") || strings.Contains(out, "pw-secret") || !strings.Contains(out, "\"keep\":1") {
		t.Errorf("json mask: %s", out)
	}
	if r.String("later tok-secret use") != "later *** use" {
		t.Error("issued secret not registered")
	}
	if r.JSON([]byte("not json")) != "not json" {
		t.Error("non-json passthrough")
	}
	if rpcFromBody([]byte("{}")) != nil {
		t.Error("no method")
	}
	if _, _, ok := rpcErrorFromBody([]byte("event: x\ndata: nope")); ok {
		t.Error("bad sse")
	}
	if maskKeepScheme("nospace") != Mask {
		t.Error("mask without scheme")
	}
}
