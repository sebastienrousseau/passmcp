// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package telemetry records every HTTP exchange passmcp makes, with
// connection-level timings from net/http/httptrace, TLS details, redacted
// headers and optionally bodies. Events can be exported as JSON, NDJSON, or
// a HAR archive that any browser devtools can open.
package telemetry

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"sort"
	"strings"
	"sync"
	"time"

	"satellion.com/passmcp/trace"
)

// Timings are per-request phase durations. Zero means the phase did not
// occur on this request (for example a reused connection has no DNS/TLS).
type Timings struct {
	DNS     time.Duration `json:"dns_ms"`
	Connect time.Duration `json:"connect_ms"`
	TLS     time.Duration `json:"tls_ms"`
	TTFB    time.Duration `json:"ttfb_ms"`
	Total   time.Duration `json:"total_ms"`
}

// MarshalJSON renders durations as fractional milliseconds.
func (t Timings) MarshalJSON() ([]byte, error) {
	ms := func(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
	return json.Marshal(map[string]float64{"dns_ms": ms(t.DNS), "connect_ms": ms(t.Connect), "tls_ms": ms(t.TLS), "ttfb_ms": ms(t.TTFB), "total_ms": ms(t.Total)})
}

// UnmarshalJSON reads those milliseconds back.
//
// Without this the struct tags win and `json` tries to read 0.169625 into a
// time.Duration, which is an integer — so a report passmcp wrote could not be
// read by passmcp. That is not a theoretical asymmetry: `passmcp attest` reads a
// saved report, and every report with telemetry events in it was unreadable
// until this existed.
func (t *Timings) UnmarshalJSON(b []byte) error {
	var raw map[string]float64
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	dur := func(key string) time.Duration {
		return time.Duration(raw[key] * float64(time.Millisecond))
	}
	t.DNS, t.Connect = dur("dns_ms"), dur("connect_ms")
	t.TLS, t.TTFB, t.Total = dur("tls_ms"), dur("ttfb_ms"), dur("total_ms")
	return nil
}

// TLSInfo describes the negotiated TLS session.
type TLSInfo struct {
	Version      string    `json:"version"`
	CipherSuite  string    `json:"cipher_suite"`
	ServerName   string    `json:"server_name"`
	Subject      string    `json:"subject,omitempty"`
	Issuer       string    `json:"issuer,omitempty"`
	NotAfter     time.Time `json:"not_after,omitempty"`
	DaysToExpiry int       `json:"days_to_expiry,omitempty"`
	Resumed      bool      `json:"resumed"`
}

// RPCInfo is the JSON-RPC view of a request/response pair.
type RPCInfo struct {
	Method       string `json:"method,omitempty"`
	ID           *int64 `json:"id,omitempty"`
	Notification bool   `json:"notification,omitempty"`
	ErrorCode    int    `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// Event is one recorded HTTP exchange.
type Event struct {
	Seq     int       `json:"seq"`
	Time    time.Time `json:"time"`
	TraceID string    `json:"trace_id,omitempty"`
	Phase   string    `json:"phase,omitempty"`
	Label   string    `json:"label,omitempty"`

	Method string `json:"method"`
	URL    string `json:"url"`
	Status int    `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`

	Remote     string   `json:"remote,omitempty"`
	ReusedConn bool     `json:"reused_conn"`
	Timings    Timings  `json:"timings"`
	TLS        *TLSInfo `json:"tls,omitempty"`

	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	RequestBytes    int64             `json:"request_bytes"`
	ResponseBytes   int64             `json:"response_bytes"`
	RequestBody     string            `json:"request_body,omitempty"`
	ResponseBody    string            `json:"response_body,omitempty"`
	ContentType     string            `json:"content_type,omitempty"`

	RPC *RPCInfo `json:"rpc,omitempty"`
}

// Summary aggregates a recording.
type Summary struct {
	Requests      int            `json:"requests"`
	Errors        int            `json:"errors"`
	BytesSent     int64          `json:"bytes_sent"`
	BytesReceived int64          `json:"bytes_received"`
	ByStatus      map[string]int `json:"by_status"`
	ByPhase       map[string]int `json:"by_phase"`
	ByHost        map[string]int `json:"by_host"`
	Wall          time.Duration  `json:"wall_ms"`
	NewConns      int            `json:"new_connections"`
}

// Recorder captures events. It is safe for concurrent use.
type Recorder struct {
	// CaptureBodies stores request and response bodies (redacted, capped
	// at BodyCap bytes). Off by default: bodies can be large and may hold
	// customer data.
	CaptureBodies bool
	BodyCap       int
	Redactor      *Redactor
	// Sink, when set, receives each event as it completes (for NDJSON
	// streaming).
	Sink func(Event)
	// MaxEvents bounds how many events are retained. Once it is reached the
	// oldest are dropped, and Summary keeps counting the dropped ones. A run
	// against a large catalog at high concurrency would otherwise grow the
	// recording without limit. Zero means DefaultMaxEvents; negative means
	// unbounded.
	MaxEvents int

	mu      sync.Mutex
	events  []Event
	seq     int
	dropped int
	first   time.Time
	last    time.Time
	// agg accumulates the summary for events that have been dropped.
	agg Summary
}

// DefaultMaxEvents is how many exchanges a recorder keeps by default.
const DefaultMaxEvents = 5000

// New returns a recorder with a fresh redactor.
func New() *Recorder {
	return &Recorder{BodyCap: 64 << 10, Redactor: &Redactor{}, MaxEvents: DefaultMaxEvents}
}

// Dropped reports how many events were discarded to stay within MaxEvents.
func (r *Recorder) Dropped() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dropped
}

type phaseKey struct{}

type phaseLabel struct{ phase, label string }

// WithPhase tags requests made under ctx with a phase and label.
func WithPhase(ctx context.Context, phase, label string) context.Context {
	return context.WithValue(ctx, phaseKey{}, phaseLabel{phase, label})
}

// Wrap returns a RoundTripper that records through r.
func (r *Recorder) Wrap(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &roundTripper{rec: r, base: base}
}

// Events returns a copy of everything recorded so far.
func (r *Recorder) Events() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Event, len(r.events))
	copy(out, r.events)
	return out
}

// maxEvents resolves the retention limit. It must be called with r.mu held
// or from a context where concurrent mutation is impossible.
func (r *Recorder) maxEvents() int {
	if r.MaxEvents == 0 {
		return DefaultMaxEvents
	}
	return r.MaxEvents
}

// accumulate folds one event into a Summary.
func accumulate(s *Summary, e Event) {
	if s.ByStatus == nil {
		s.ByStatus, s.ByPhase, s.ByHost = map[string]int{}, map[string]int{}, map[string]int{}
	}
	s.Requests++
	if e.Error != "" {
		s.Errors++
	}
	s.BytesSent += e.RequestBytes
	s.BytesReceived += e.ResponseBytes
	// A status code is an HTTP thing. A pipe has none, and bucketing every
	// stdio message under "error" made a clean run's summary read as a
	// hundred failures.
	key := "error"
	switch {
	case e.Status > 0:
		key = fmt.Sprintf("%dxx", e.Status/100)
	case e.Error == "":
		key = "ok"
	}
	s.ByStatus[key]++
	if e.Phase != "" {
		s.ByPhase[e.Phase]++
	}
	if i := strings.Index(e.URL, "//"); i >= 0 {
		host := e.URL[i+2:]
		if j := strings.IndexByte(host, '/'); j >= 0 {
			host = host[:j]
		}
		s.ByHost[host]++
	}
	if !e.ReusedConn {
		s.NewConns++
	}
}

// Summary aggregates the recording, including events dropped to stay within
// MaxEvents.
func (r *Recorder) Summary() Summary {
	s := Summary{ByStatus: map[string]int{}, ByPhase: map[string]int{}, ByHost: map[string]int{}}
	r.mu.Lock()
	base := r.agg
	evs := make([]Event, len(r.events))
	copy(evs, r.events)
	first, last := r.first, r.last
	r.mu.Unlock()

	s.Requests, s.Errors = base.Requests, base.Errors
	s.BytesSent, s.BytesReceived, s.NewConns = base.BytesSent, base.BytesReceived, base.NewConns
	for k, v := range base.ByStatus {
		s.ByStatus[k] += v
	}
	for k, v := range base.ByPhase {
		s.ByPhase[k] += v
	}
	for k, v := range base.ByHost {
		s.ByHost[k] += v
	}
	for _, e := range evs {
		accumulate(&s, e)
	}
	if !first.IsZero() {
		s.Wall = last.Sub(first)
	}
	return s
}

func (r *Recorder) add(e Event) {
	r.mu.Lock()
	r.seq++
	e.Seq = r.seq
	r.events = append(r.events, e)
	if maxEv := r.maxEvents(); maxEv > 0 && len(r.events) > maxEv {
		// Fold the evicted events into the running aggregate so the summary
		// still describes the whole run, then drop them.
		drop := len(r.events) - maxEv
		for _, old := range r.events[:drop] {
			accumulate(&r.agg, old)
		}
		r.dropped += drop
		r.events = append(r.events[:0], r.events[drop:]...)
	}
	if r.first.IsZero() {
		r.first = e.Time
	}
	if end := e.Time.Add(e.Timings.Total); end.After(r.last) {
		r.last = end
	}
	sink := r.Sink
	r.mu.Unlock()
	if sink != nil {
		sink(e)
	}
}

// PipeMethod is the Event.Method of an exchange that was not HTTP.
//
// It is not an HTTP verb on purpose. A reader who sees POST beside a
// stdio: URL will assume a request was made over the network, and every
// derived rendering — the HAR, the trace, the summary — would carry that
// assumption forward.
const PipeMethod = "PIPE"

// RecordPipe records one message exchange over a pipe.
//
// A pipe has no status code, no headers, no connection and no DNS, so this
// fills what it does have and leaves the rest zero. It exists because the
// alternative is a stdio run whose findings cite no evidence at all, while
// the same findings over HTTP cite "req#7" — a report that reads as
// thinner for a reason that has nothing to do with the server.
//
// target names what is on the other end (the command passmcp ran). It is put
// through the redactor because a command line is a place secrets live:
// "--api-key=..." in an argument is ordinary, and it must not reach a
// report.
func (r *Recorder) RecordPipe(ctx context.Context, target string, sent, received []byte, d time.Duration, err error) {
	red := r.Redactor
	ev := Event{
		Time:          time.Now().Add(-d),
		TraceID:       trace.FromContext(ctx),
		Method:        PipeMethod,
		URL:           "stdio:" + red.String(target),
		RequestBytes:  int64(len(sent)),
		ResponseBytes: int64(len(received)),
		ContentType:   "application/jsonl",
		Timings:       Timings{Total: d, TTFB: d},
		// A pipe is one connection for the life of the run, so every
		// exchange after the first reuses it. Saying otherwise would make
		// the summary count a new connection per message.
		ReusedConn: true,
	}
	if pl, ok := ctx.Value(phaseKey{}).(phaseLabel); ok {
		ev.Phase, ev.Label = pl.phase, pl.label
	}
	if err != nil {
		ev.Error = red.String(err.Error())
	}
	if len(sent) > 0 {
		ev.RPC = rpcFromBody(sent)
		if r.CaptureBodies {
			ev.RequestBody = r.captureBody("application/json", sent, int64(len(sent)))
		}
	}
	if len(received) > 0 {
		r.recordPipeResponse(&ev, received)
	}
	r.add(ev)
}

// recordPipeResponse captures a pipe exchange's response on ev, or, when
// bodies are not captured, still registers any secret it issues, and
// copies a JSON-RPC error onto the request's RPC record.
func (r *Recorder) recordPipeResponse(ev *Event, received []byte) {
	r.Redactor.registerPersonalFromResponse(ev.RPC, received)
	if r.CaptureBodies {
		ev.ResponseBody = r.captureBody("application/json", received, int64(len(received)))
	} else if looksJSON(received) {
		_ = r.Redactor.JSON(received) // register issued secrets
	}
	if ev.RPC != nil {
		if code, msg, ok := rpcErrorFromBody(received); ok {
			ev.RPC.ErrorCode, ev.RPC.ErrorMessage = code, msg
		}
	}
}

type roundTripper struct {
	rec  *Recorder
	base http.RoundTripper
}

// RoundTrip implements http.RoundTripper, recording one Event per exchange.
func (t *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := t.rec
	red := rec.Redactor
	ev := Event{Time: time.Now(), TraceID: trace.FromContext(req.Context()), Method: req.Method, URL: red.URL(req.URL.String())}
	if pl, ok := req.Context().Value(phaseKey{}).(phaseLabel); ok {
		ev.Phase, ev.Label = pl.phase, pl.label
	}
	ev.RequestHeaders = redactHeaders(red, req.Header)

	if err := rec.captureRequest(req, &ev); err != nil {
		return nil, err
	}

	var (
		mu                                   sync.Mutex
		dnsStart, connStart, tlsStart, start time.Time
		t0                                   = time.Now()
	)
	start = t0
	ct := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { mu.Lock(); dnsStart = time.Now(); mu.Unlock() },
		DNSDone: func(httptrace.DNSDoneInfo) {
			mu.Lock()
			if !dnsStart.IsZero() {
				ev.Timings.DNS = time.Since(dnsStart)
			}
			mu.Unlock()
		},
		ConnectStart: func(string, string) { mu.Lock(); connStart = time.Now(); mu.Unlock() },
		ConnectDone: func(_, addr string, err error) {
			mu.Lock()
			if !connStart.IsZero() {
				ev.Timings.Connect = time.Since(connStart)
			}
			mu.Unlock()
		},
		TLSHandshakeStart: func() { mu.Lock(); tlsStart = time.Now(); mu.Unlock() },
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			mu.Lock()
			if !tlsStart.IsZero() {
				ev.Timings.TLS = time.Since(tlsStart)
			}
			if err == nil {
				ev.TLS = tlsInfo(cs)
			}
			mu.Unlock()
		},
		GotConn: func(info httptrace.GotConnInfo) {
			mu.Lock()
			ev.ReusedConn = info.Reused
			if info.Conn != nil {
				ev.Remote = info.Conn.RemoteAddr().String()
			}
			mu.Unlock()
		},
		GotFirstResponseByte: func() { mu.Lock(); ev.Timings.TTFB = time.Since(start); mu.Unlock() },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), ct))

	resp, err := t.base.RoundTrip(req)
	if err != nil {
		mu.Lock()
		ev.Error = red.String(err.Error())
		ev.Timings.Total = time.Since(t0)
		// Copy under the lock. httptrace callbacks are not finished when
		// RoundTrip returns — net/http dials in a background goroutine and
		// fires ConnectStart/ConnectDone against this same trace even after
		// the request it was started for has failed. Passing ev to add by
		// value reads every field, so doing it unlocked races that write.
		// This is what bodyRecorder.finish already does on the success path.
		failed := ev
		mu.Unlock()
		rec.add(failed)
		return nil, err
	}
	mu.Lock()
	ev.Status = resp.StatusCode
	ev.ResponseHeaders = redactHeaders(red, resp.Header)
	ev.ContentType = resp.Header.Get("Content-Type")
	if ev.TLS == nil && resp.TLS != nil {
		ev.TLS = tlsInfo(*resp.TLS)
	}
	contentType := ev.ContentType
	mu.Unlock()
	// Finalize when the body is fully read or closed so byte counts and
	// total time include the body. The content type is read above rather
	// than here, for
	// the same reason: a late callback may still be writing to ev.
	resp.Body = &bodyRecorder{rc: resp.Body, rec: rec, ev: &ev, mu: &mu, t0: t0, ct: contentType}
	return resp, nil
}

// captureRequest records the request body's size, capture and JSON-RPC
// shape on ev, then puts the body back so the request can still be sent.
func (r *Recorder) captureRequest(req *http.Request, ev *Event) error {
	// Request body: read once for size/capture, then replay.
	if req.Body != nil && req.Body != http.NoBody {
		b, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return err
		}
		ev.RequestBytes = int64(len(b))
		if r.CaptureBodies {
			ev.RequestBody = r.captureBody(req.Header.Get("Content-Type"), b, int64(len(b)))
		}
		req.Body = io.NopCloser(bytes.NewReader(b))
		if req.GetBody == nil {
			req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
		}
		ev.RPC = rpcFromBody(b)
	}
	return nil
}

type bodyRecorder struct {
	rc   io.ReadCloser
	rec  *Recorder
	ev   *Event
	mu   *sync.Mutex
	t0   time.Time
	ct   string
	buf  bytes.Buffer
	n    int64
	done bool
}

// rpcSniffCap is how much of a body is always retained so a JSON-RPC error
// can be extracted from it, independent of BodyCap. Without it, a small
// --body-cap would silently stop the report from naming RPC errors.
const rpcSniffCap = 8 << 10

// bufCap is how much of the body this recorder retains.
func (b *bodyRecorder) bufCap() int {
	return max(b.rec.BodyCap, rpcSniffCap)
}

// Read implements io.Reader. net/http may Close a response body from
// another goroutine while a Read is in flight (context cancellation does
// exactly that), so the counters this shares with finish are guarded.
func (b *bodyRecorder) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	b.mu.Lock()
	b.n += int64(n)
	if room := b.bufCap() - b.buf.Len(); room > 0 && n > 0 {
		b.buf.Write(p[:min(n, room)])
	}
	b.mu.Unlock()
	if err == io.EOF {
		b.finish()
	}
	return n, err
}

// Close finalizes the event if EOF was never reached.
func (b *bodyRecorder) Close() error {
	err := b.rc.Close()
	b.finish()
	return err
}

func (b *bodyRecorder) finish() {
	b.mu.Lock()
	if b.done {
		b.mu.Unlock()
		return
	}
	b.done = true
	b.ev.ResponseBytes = b.n
	b.ev.Timings.Total = time.Since(b.t0)
	b.rec.Redactor.registerPersonalFromResponse(b.ev.RPC, b.buf.Bytes())
	if b.rec.CaptureBodies {
		b.ev.ResponseBody = b.rec.captureBody(b.ct, b.buf.Bytes(), b.n)
	} else if looksJSON(b.buf.Bytes()) {
		_ = b.rec.Redactor.JSON(b.buf.Bytes()) // register issued secrets
	}
	if b.ev.RPC != nil && b.buf.Len() > 0 {
		if code, msg, ok := rpcErrorFromBody(b.buf.Bytes()); ok {
			b.ev.RPC.ErrorCode, b.ev.RPC.ErrorMessage = code, msg
		}
	}
	ev := *b.ev
	b.mu.Unlock()
	b.rec.add(ev)
}

// captureBody renders a body for the report. total is the true size of the
// body on the wire, which may exceed what was retained.
func (r *Recorder) captureBody(contentType string, b []byte, total int64) string {
	if len(b) == 0 {
		return ""
	}
	capped := b
	truncated := total > int64(r.BodyCap)
	if len(capped) > r.BodyCap {
		capped = capped[:r.BodyCap]
	}
	var s string
	switch {
	case strings.HasPrefix(contentType, "application/x-www-form-urlencoded"):
		s = r.Redactor.Form(string(capped))
	case looksJSON(capped):
		// A truncated body will not parse as JSON, so key-based masking
		// cannot run over it. Fall back to masking by key name on the raw
		// text: a token cut in half is still a token, and the half that
		// survives must not reach a report file.
		s = r.Redactor.JSONOrKeys(capped)
	default:
		s = r.Redactor.String(string(capped))
	}
	// E-mail addresses and phone numbers are masked in every captured
	// body, whatever key or none they sit under (personal.go).
	s = r.Redactor.maskPersonalPatterns(s)
	if truncated {
		s += fmt.Sprintf("…[truncated %d bytes]", total-int64(r.BodyCap))
	}
	return s
}

func redactHeaders(red *Redactor, h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, vs := range h {
		out[k] = red.Header(k, strings.Join(vs, ", "))
	}
	return out
}

func rpcFromBody(b []byte) *RPCInfo {
	var probe struct {
		Method string `json:"method"`
		ID     *int64 `json:"id"`
	}
	if json.Unmarshal(b, &probe) != nil || probe.Method == "" {
		return nil
	}
	return &RPCInfo{Method: probe.Method, ID: probe.ID, Notification: probe.ID == nil}
}

func rpcErrorFromBody(b []byte) (int, string, bool) {
	// Works for a JSON body; for SSE, find the first data: line.
	if bytes.HasPrefix(bytes.TrimSpace(b), []byte("event:")) || bytes.HasPrefix(bytes.TrimSpace(b), []byte("data:")) {
		for _, line := range bytes.Split(b, []byte("\n")) {
			if bytes.HasPrefix(line, []byte("data:")) {
				b = bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
				break
			}
		}
	}
	var probe struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(b, &probe) != nil || probe.Error == nil {
		return 0, "", false
	}
	return probe.Error.Code, probe.Error.Message, true
}

func tlsInfo(cs tls.ConnectionState) *TLSInfo {
	info := &TLSInfo{Version: tls.VersionName(cs.Version), CipherSuite: tls.CipherSuiteName(cs.CipherSuite), ServerName: cs.ServerName, Resumed: cs.DidResume}
	if len(cs.PeerCertificates) > 0 {
		c := cs.PeerCertificates[0]
		info.Subject = c.Subject.String()
		info.Issuer = c.Issuer.String()
		info.NotAfter = c.NotAfter
		info.DaysToExpiry = int(time.Until(c.NotAfter).Hours() / 24)
	}
	return info
}

// WriteNDJSON writes one event per line.
func (r *Recorder) WriteNDJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	for _, e := range r.Events() {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	return nil
}

// WriteHAR writes the recording as an HTTP Archive 1.2 document.
func (r *Recorder) WriteHAR(w io.Writer, creatorVersion string) error {
	type nv struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	headers := func(m map[string]string) []nv {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make([]nv, 0, len(keys))
		for _, k := range keys {
			out = append(out, nv{k, m[k]})
		}
		return out
	}
	ms := func(d time.Duration) float64 {
		if d <= 0 {
			return -1
		}
		return float64(d) / float64(time.Millisecond)
	}
	entries := make([]map[string]any, 0)
	for _, e := range r.Events() {
		wait := e.Timings.TTFB - e.Timings.DNS - e.Timings.Connect - e.Timings.TLS
		if wait < 0 {
			wait = e.Timings.TTFB
		}
		recv := e.Timings.Total - e.Timings.TTFB
		if recv < 0 {
			recv = 0
		}
		req := map[string]any{"method": e.Method, "url": e.URL, "httpVersion": "HTTP/1.1", "headers": headers(e.RequestHeaders), "queryString": []nv{}, "cookies": []nv{}, "headersSize": -1, "bodySize": e.RequestBytes}
		if e.RequestBody != "" {
			req["postData"] = map[string]any{"mimeType": e.RequestHeaders["Content-Type"], "text": e.RequestBody}
		}
		content := map[string]any{"size": e.ResponseBytes, "mimeType": e.ContentType}
		if e.ResponseBody != "" {
			content["text"] = e.ResponseBody
		}
		status := e.Status
		statusText := http.StatusText(status)
		if e.Error != "" {
			statusText = e.Error
		}
		entries = append(entries, map[string]any{
			"startedDateTime": e.Time.Format(time.RFC3339Nano),
			"time":            ms(e.Timings.Total),
			"request":         req,
			"response":        map[string]any{"status": status, "statusText": statusText, "httpVersion": "HTTP/1.1", "headers": headers(e.ResponseHeaders), "cookies": []nv{}, "content": content, "redirectURL": "", "headersSize": -1, "bodySize": e.ResponseBytes},
			"cache":           map[string]any{},
			"timings":         map[string]any{"blocked": -1, "dns": ms(e.Timings.DNS), "connect": ms(e.Timings.Connect), "ssl": ms(e.Timings.TLS), "send": 0, "wait": ms(wait), "receive": float64(recv) / float64(time.Millisecond)},
			"serverIPAddress": strings.Split(e.Remote, ":")[0],
			"comment":         strings.TrimSpace(e.Phase + " " + e.Label),
		})
	}
	doc := map[string]any{"log": map[string]any{"version": "1.2", "creator": map[string]string{"name": "passmcp", "version": creatorVersion}, "entries": entries}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// Count returns how many events have been recorded, including any dropped
// to stay within MaxEvents. It is monotonic, so a finding's evidence range
// stays meaningful across an eviction.
func (r *Recorder) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seq
}

// looksJSON reports whether b starts like a JSON object or array. Content
// types lie often enough (token endpoints answering text/plain) that the
// shape is the better signal.
func looksJSON(b []byte) bool {
	t := bytes.TrimSpace(b)
	return len(t) > 0 && (t[0] == '{' || t[0] == '[')
}
