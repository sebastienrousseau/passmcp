// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package otlp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/telemetry"
)

func sampleRun() Run {
	start := time.Date(2026, 9, 18, 9, 0, 0, 0, time.UTC)
	return Run{
		TraceID:    "0123456789abcdef0123456789abcdef",
		Endpoint:   "https://mcp.example.com/mcp",
		Host:       "mcp.example.com",
		Started:    start,
		Duration:   3 * time.Second,
		Failed:     1,
		Warned:     2,
		ScoreTotal: 72.5,
		Phases: []probe.PhaseResult{
			{
				Name: "net", Title: "Network", Status: probe.Pass,
				Started: start, Duration: probe.Millis(500 * time.Millisecond),
				Summary: "reachable",
				Findings: []probe.Finding{
					{ID: "net.dns", Phase: "net", Title: "Resolves", Status: probe.Pass, DocURL: "https://satellion.com/passmcp/docs/checks/#check-net-dns"},
				},
			},
			{
				Name: "protocol", Title: "Protocol", Status: probe.Fail,
				Started: start.Add(500 * time.Millisecond), Duration: probe.Millis(time.Second),
				Findings: []probe.Finding{
					{ID: "protocol.malformed_json", Phase: "protocol", Title: "Malformed JSON rejected",
						Status: probe.Fail, Severity: probe.Minor, Detail: "HTTP 200", Advice: "return 400",
						Evidence: []string{"req#8"}},
				},
			},
			{Name: "auth", Title: "Auth", Status: probe.Skip, Started: start, Skipped: "no credentials"},
		},
		Events: []telemetry.Event{
			{Seq: 1, Time: start, Phase: "net", Method: "GET", URL: "https://mcp.example.com/mcp",
				Status: 200, Remote: "93.184.216.34:443", ReusedConn: false,
				RequestBytes: 120, ResponseBytes: 340,
				Timings: telemetry.Timings{DNS: 4 * time.Millisecond, Connect: 11 * time.Millisecond, TTFB: 90 * time.Millisecond, Total: 100 * time.Millisecond}},
			{Seq: 2, Time: start.Add(time.Second), Phase: "protocol", Method: "POST", URL: "https://mcp.example.com/mcp",
				Status: 500, Error: "boom",
				RPC:     &telemetry.RPCInfo{Method: "tools/call", ErrorCode: -32603, ErrorMessage: "internal"},
				Timings: telemetry.Timings{Total: 50 * time.Millisecond}},
			// A request nothing attributed to a phase. It must still appear.
			{Seq: 3, Time: start.Add(2 * time.Second), Method: "GET", URL: "https://mcp.example.com/.well-known", Status: 404,
				Timings: telemetry.Timings{Total: 10 * time.Millisecond}},
		},
	}
}

// decode is the shape a collector parses back out.
type decoded struct {
	ResourceSpans []struct {
		Resource struct {
			Attributes []struct {
				Key   string `json:"key"`
				Value struct {
					StringValue *string  `json:"stringValue"`
					IntValue    *string  `json:"intValue"`
					DoubleValue *float64 `json:"doubleValue"`
					BoolValue   *bool    `json:"boolValue"`
				} `json:"value"`
			} `json:"attributes"`
		} `json:"resource"`
		ScopeSpans []struct {
			Scope struct {
				Name string `json:"name"`
			} `json:"scope"`
			Spans []struct {
				TraceID           string `json:"traceId"`
				SpanID            string `json:"spanId"`
				ParentSpanID      string `json:"parentSpanId"`
				Name              string `json:"name"`
				Kind              int    `json:"kind"`
				StartTimeUnixNano string `json:"startTimeUnixNano"`
				EndTimeUnixNano   string `json:"endTimeUnixNano"`
				Attributes        []struct {
					Key   string `json:"key"`
					Value struct {
						StringValue *string  `json:"stringValue"`
						IntValue    *string  `json:"intValue"`
						DoubleValue *float64 `json:"doubleValue"`
						BoolValue   *bool    `json:"boolValue"`
					} `json:"value"`
				} `json:"attributes"`
				Events []struct {
					Name         string `json:"name"`
					TimeUnixNano string `json:"timeUnixNano"`
				} `json:"events"`
				Status *struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
				} `json:"status"`
			} `json:"spans"`
		} `json:"scopeSpans"`
	} `json:"resourceSpans"`
}

func export(t *testing.T, r Run) (decoded, http.Header) {
	t.Helper()
	var body []byte
	var hdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		hdr = req.Header.Clone()
		body, _ = readAll(req)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	e := Exporter{Endpoint: srv.URL + "/v1/traces", ServiceVersion: "1.2.3", Headers: map[string]string{"X-Tenant": "acme"}}
	if err := e.Export(context.Background(), r); err != nil {
		t.Fatalf("Export: %v", err)
	}
	var doc decoded
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("payload is not valid JSON: %v\n%s", err, body)
	}
	return doc, hdr
}

func readAll(req *http.Request) ([]byte, error) {
	defer func() { _ = req.Body.Close() }()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := req.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			return buf, nil
		}
	}
}

// TestExportShape covers what a collector rejects a payload for: an id that
// is not hex of the right length, a timestamp that is a number rather than
// a decimal string, or a parent that names no span in the batch.
func TestExportShape(t *testing.T) {
	doc, hdr := export(t, sampleRun())

	if hdr.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q", hdr.Get("Content-Type"))
	}
	if hdr.Get("X-Tenant") != "acme" {
		t.Errorf("configured header not sent: %v", hdr.Get("X-Tenant"))
	}
	if len(doc.ResourceSpans) != 1 || len(doc.ResourceSpans[0].ScopeSpans) != 1 {
		t.Fatalf("unexpected envelope: %+v", doc)
	}

	spans := doc.ResourceSpans[0].ScopeSpans[0].Spans
	// 1 root + 3 phases + 3 requests.
	if len(spans) != 7 {
		t.Fatalf("got %d spans, want 7", len(spans))
	}

	ids := map[string]bool{}
	for _, s := range spans {
		if len(s.TraceID) != 32 {
			t.Errorf("%s: traceId %q is not 32 hex characters", s.Name, s.TraceID)
		}
		if _, err := hex.DecodeString(s.TraceID); err != nil {
			t.Errorf("%s: traceId is not hex: %v", s.Name, err)
		}
		if len(s.SpanID) != 16 {
			t.Errorf("%s: spanId %q is not 16 hex characters", s.Name, s.SpanID)
		}
		if _, err := hex.DecodeString(s.SpanID); err != nil {
			t.Errorf("%s: spanId is not hex: %v", s.Name, err)
		}
		if ids[s.SpanID] {
			t.Errorf("%s: duplicate span id %s", s.Name, s.SpanID)
		}
		ids[s.SpanID] = true

		for _, field := range []string{s.StartTimeUnixNano, s.EndTimeUnixNano} {
			if _, err := strconv.ParseUint(field, 10, 64); err != nil {
				t.Errorf("%s: %q is not a decimal nanosecond string", s.Name, field)
			}
		}
		if s.EndTimeUnixNano < s.StartTimeUnixNano {
			t.Errorf("%s: ends before it starts", s.Name)
		}
	}

	// Every parent must be present in the same batch, or the collector
	// shows an orphan.
	var roots int
	for _, s := range spans {
		if s.ParentSpanID == "" {
			roots++
			continue
		}
		if !ids[s.ParentSpanID] {
			t.Errorf("%s: parent %s is not in the batch", s.Name, s.ParentSpanID)
		}
	}
	if roots != 1 {
		t.Errorf("got %d root spans, want exactly 1", roots)
	}

	if doc.ResourceSpans[0].ScopeSpans[0].Scope.Name != "satellion.com/passmcp" {
		t.Errorf("scope = %q", doc.ResourceSpans[0].ScopeSpans[0].Scope.Name)
	}
	if v := resourceAttr(doc, "service.name"); v != "passmcp" {
		t.Errorf("service.name = %q", v)
	}
	if v := resourceAttr(doc, "service.version"); v != "1.2.3" {
		t.Errorf("service.version = %q", v)
	}
}

// TestUnattributedRequestStillAppears is the property that keeps the trace
// honest: a request passmcp made outside a phase is still a request it made.
func TestUnattributedRequestStillAppears(t *testing.T) {
	doc, _ := export(t, sampleRun())
	spans := doc.ResourceSpans[0].ScopeSpans[0].Spans
	var found bool
	for _, s := range spans {
		if strings.Contains(s.Name, ".well-known") {
			found = true
			if s.ParentSpanID == "" {
				t.Error("the unattributed request has no parent at all")
			}
			if s.ParentSpanID != spans[0].SpanID {
				t.Errorf("unattributed request parented to %s, want the root %s", s.ParentSpanID, spans[0].SpanID)
			}
		}
	}
	if !found {
		t.Error("the request with no phase was dropped")
	}
}

// TestStatusAndEvents checks the two things somebody opens a trace for: did
// it fail, and what did it say.
func TestStatusAndEvents(t *testing.T) {
	doc, _ := export(t, sampleRun())
	spans := doc.ResourceSpans[0].ScopeSpans[0].Spans

	byName := map[string]int{}
	for i, s := range spans {
		byName[s.Name] = i
	}

	root := spans[byName["passmcp check"]]
	if root.Status == nil || root.Status.Code != statusCodeError {
		t.Errorf("root status = %+v, want error (the run had a failing finding)", root.Status)
	}

	proto := spans[byName["phase protocol"]]
	if proto.Status == nil || proto.Status.Code != statusCodeError {
		t.Errorf("failing phase status = %+v, want error", proto.Status)
	}
	if len(proto.Events) != 1 || proto.Events[0].Name != "protocol.malformed_json" {
		t.Errorf("findings did not become span events: %+v", proto.Events)
	}

	netPhase := spans[byName["phase net"]]
	if netPhase.Status == nil || netPhase.Status.Code != statusCodeOK {
		t.Errorf("passing phase status = %+v, want ok", netPhase.Status)
	}

	for _, s := range spans {
		if strings.HasPrefix(s.Name, "POST ") {
			if s.Status == nil || s.Status.Code != statusCodeError {
				t.Errorf("a 500 with an error produced status %+v", s.Status)
			}
			if got := spanAttr(s.Attributes, "rpc.method"); got != "tools/call" {
				t.Errorf("rpc.method = %q", got)
			}
		}
	}
}

// TestIntAttributesAreStrings pins the proto3 JSON mapping. A collector
// rejects an int64 sent as a JSON number, and the mistake is invisible
// until something downstream silently drops the attribute.
func TestIntAttributesAreStrings(t *testing.T) {
	e := Exporter{Endpoint: "https://collector.invalid", ServiceVersion: "t"}
	b, err := json.Marshal(e.build(sampleRun()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"intValue":"200"`) {
		t.Errorf("http.response.status_code is not a string-encoded int:\n%s", b)
	}
	if strings.Contains(string(b), `"intValue":200`) {
		t.Error("an int64 attribute was encoded as a JSON number")
	}
	if !strings.Contains(string(b), `"startTimeUnixNano":"`) {
		t.Error("timestamps are not string-encoded")
	}
}

func TestTracesURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://collector:4318":           "https://collector:4318/v1/traces",
		"https://collector:4318/":          "https://collector:4318/v1/traces",
		"https://collector:4318/v1/traces": "https://collector:4318/v1/traces",
		"https://collector/otlp/v1/traces": "https://collector/otlp/v1/traces",
		"http://localhost:4318":            "http://localhost:4318/v1/traces",
	} {
		if got := tracesURL(in); got != want {
			t.Errorf("tracesURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestExportFailureIsReported: an unreachable collector must return an
// error rather than pretend. Whether that ends the run is the caller's
// decision, and passmcp's answer is that it must not.
func TestExportFailureIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusBadRequest)
	}))
	defer srv.Close()
	e := Exporter{Endpoint: srv.URL + "/v1/traces"}
	err := e.Export(context.Background(), sampleRun())
	if err == nil {
		t.Fatal("a 400 from the collector was reported as success")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error does not name the status: %v", err)
	}
}

// TestNoEndpointIsNotAnError keeps the flag optional.
func TestNoEndpointIsNotAnError(t *testing.T) {
	if err := (Exporter{}).Export(context.Background(), sampleRun()); err != nil {
		t.Errorf("Export with no endpoint = %v, want nil", err)
	}
}

// TestBadTraceIDIsReplaced: passmcp's ids are already 32 hex characters, but
// a caller could pass anything, and a malformed id makes the collector
// reject the whole batch rather than the one span.
func TestBadTraceIDIsReplaced(t *testing.T) {
	r := sampleRun()
	r.TraceID = "not-a-trace-id"
	doc, _ := export(t, r)
	for _, s := range doc.ResourceSpans[0].ScopeSpans[0].Spans {
		if len(s.TraceID) != 32 {
			t.Fatalf("traceId = %q", s.TraceID)
		}
		if _, err := hex.DecodeString(s.TraceID); err != nil {
			t.Fatalf("traceId is not hex: %v", err)
		}
	}
}

func resourceAttr(d decoded, key string) string {
	for _, a := range d.ResourceSpans[0].Resource.Attributes {
		if a.Key == key && a.Value.StringValue != nil {
			return *a.Value.StringValue
		}
	}
	return ""
}

func spanAttr(attrs []struct {
	Key   string `json:"key"`
	Value struct {
		StringValue *string  `json:"stringValue"`
		IntValue    *string  `json:"intValue"`
		DoubleValue *float64 `json:"doubleValue"`
		BoolValue   *bool    `json:"boolValue"`
	} `json:"value"`
}, key string) string {
	for _, a := range attrs {
		if a.Key == key && a.Value.StringValue != nil {
			return *a.Value.StringValue
		}
	}
	return ""
}
