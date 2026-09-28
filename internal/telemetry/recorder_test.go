// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp/trace"
)

func TestRecorderCapturesTimingsHeadersAndRedacts(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=abc")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":7,"error":{"code":-32601,"message":"nope"}}`))
	}))
	defer srv.Close()
	rec := New()
	rec.CaptureBodies = true
	rec.Redactor.Add("s3cr3t-token-value")
	hc := &http.Client{Transport: rec.Wrap(srv.Client().Transport)}
	ctx := WithPhase(trace.WithID(context.Background(), "t1"), "protocol", "unknown method")
	req, _ := http.NewRequestWithContext(ctx, "POST", srv.URL+"/mcp?code=oauthcode", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":7,"method":"x","token":"s3cr3t-token-value"}`)))
	req.Header.Set("Authorization", "Bearer s3cr3t-token-value")
	req.Header.Set("X-Api-Key", "k")
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = bytes.NewBuffer(nil).ReadFrom(resp.Body)
	_ = resp.Body.Close()
	evs := rec.Events()
	if len(evs) != 1 {
		t.Fatalf("events = %d", len(evs))
	}
	e := evs[0]
	if e.Phase != "protocol" || e.Label != "unknown method" || e.TraceID != "t1" || e.Status != 200 {
		t.Errorf("event = %+v", e)
	}
	if e.Timings.Total == 0 || e.Timings.TTFB == 0 || e.Timings.TLS == 0 {
		t.Errorf("timings not captured: %+v", e.Timings)
	}
	// Connect is measured separately. A loopback connection completes in
	// microseconds, and Windows' default timer granularity is coarse enough
	// to round that to zero — which says nothing about whether the hook
	// fired. Elsewhere a zero here would mean the ConnectStart/ConnectDone
	// pair was lost, which is worth catching.
	if runtime.GOOS != "windows" && e.Timings.Connect == 0 {
		t.Errorf("connect timing not captured: %+v", e.Timings)
	}
	if e.TLS == nil || e.TLS.Version == "" {
		t.Errorf("tls info missing: %+v", e.TLS)
	}
	if e.RequestHeaders["Authorization"] != "Bearer ***" || e.RequestHeaders["X-Api-Key"] != "***" || e.ResponseHeaders["Set-Cookie"] != "***" {
		t.Errorf("headers not redacted: %v %v", e.RequestHeaders, e.ResponseHeaders)
	}
	if strings.Contains(e.RequestBody, "s3cr3t") || !strings.Contains(e.RequestBody, "***") {
		t.Errorf("body not redacted: %s", e.RequestBody)
	}
	if !strings.Contains(e.URL, "code=%2A%2A%2A") && !strings.Contains(e.URL, "code=***") {
		t.Errorf("query param not redacted: %s", e.URL)
	}
	if e.RPC == nil || e.RPC.Method != "x" || e.RPC.ErrorCode != -32601 {
		t.Errorf("rpc info = %+v", e.RPC)
	}
	if e.RequestBytes == 0 || e.ResponseBytes == 0 {
		t.Errorf("bytes = %d/%d", e.RequestBytes, e.ResponseBytes)
	}
	var har bytes.Buffer
	if err := rec.WriteHAR(&har, "test"); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(har.Bytes(), &doc); err != nil {
		t.Fatalf("har not json: %v", err)
	}
	if strings.Contains(har.String(), "s3cr3t") {
		t.Error("secret leaked into HAR")
	}
	var nd bytes.Buffer
	_ = rec.WriteNDJSON(&nd)
	if strings.Count(nd.String(), "\n") != 1 {
		t.Errorf("ndjson lines = %d", strings.Count(nd.String(), "\n"))
	}
	s := rec.Summary()
	if s.Requests != 1 || s.ByStatus["2xx"] != 1 || s.ByPhase["protocol"] != 1 || s.NewConns != 1 {
		t.Errorf("summary = %+v", s)
	}
}

func TestRecorderRecordsTransportErrors(t *testing.T) {
	rec := New()
	hc := &http.Client{Transport: rec.Wrap(nil)}
	_, err := hc.Get("http://127.0.0.1:1/unreachable")
	if err == nil {
		t.Fatal("expected error")
	}
	evs := rec.Events()
	if len(evs) != 1 || evs[0].Error == "" || evs[0].Status != 0 {
		t.Errorf("events = %+v", evs)
	}
}

func TestRedactor(t *testing.T) {
	r := &Redactor{}
	r.Add("abc") // too short, ignored
	r.Add("longsecret")
	r.Add("longsecret-extended")
	if got := r.String("x longsecret-extended y longsecret z"); got != "x *** y *** z" {
		t.Errorf("got %q", got)
	}
	if got := r.Form("grant_type=x&client_secret=longsecret&refresh_token=rt1234"); strings.Contains(got, "rt1234") || strings.Contains(got, "longsecret") {
		t.Errorf("form = %q", got)
	}
	if got := r.URL("https://u:pw@h/p?state=s&x=1"); !strings.Contains(got, "state=%2A%2A%2A") || strings.Contains(got, "pw@") {
		t.Errorf("url = %q", got)
	}
	if got := r.Header("Authorization", "Basic dXNlcjpwYXNz"); got != "Basic ***" {
		t.Errorf("header = %q", got)
	}
	if got := r.Header("Content-Type", "application/json"); got != "application/json" {
		t.Errorf("plain header = %q", got)
	}
}

// A report passmcp writes must be a report passmcp can read. Timings had only a
// marshaller, so the struct tags decided how it was read back and `json`
// tried to put 0.169625 into a time.Duration — every saved report that
// carried telemetry events was write-only, and nothing noticed until
// `passmcp attest` tried to read one.
func TestTimingsRoundTrip(t *testing.T) {
	in := Timings{
		DNS:     1234 * time.Microsecond,
		Connect: 169*time.Microsecond + 625*time.Nanosecond,
		TLS:     0,
		TTFB:    12 * time.Millisecond,
		Total:   1500 * time.Microsecond,
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	// The wire form is what a consumer reads, so assert it too: a
	// round-trip through a changed encoding would still pass on its own.
	if !strings.Contains(string(b), `"ttfb_ms":12`) {
		t.Errorf("milliseconds are not on the wire: %s", b)
	}

	var out Timings
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("passmcp cannot read what passmcp wrote: %v\n%s", err, b)
	}
	// Microsecond tolerance: the wire carries fractional milliseconds as a
	// float64, so the nanosecond is not expected to survive.
	for _, c := range []struct {
		name      string
		want, got time.Duration
	}{
		{"dns", in.DNS, out.DNS},
		{"connect", in.Connect, out.Connect},
		{"tls", in.TLS, out.TLS},
		{"ttfb", in.TTFB, out.TTFB},
		{"total", in.Total, out.Total},
	} {
		if d := c.got - c.want; d > time.Microsecond || d < -time.Microsecond {
			t.Errorf("%s: %v came back as %v", c.name, c.want, c.got)
		}
	}
}
