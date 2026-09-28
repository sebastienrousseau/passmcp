// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResultType(t *testing.T) {
	cases := map[string]string{
		``:                                   ResultComplete,
		`{}`:                                 ResultComplete, // absent means complete
		`{"resultType":"complete"}`:          ResultComplete,
		`{"resultType":"input_required"}`:    ResultInputRequired,
		`{"resultType":"io.example/custom"}`: "io.example/custom",
		`not json`:                           ResultComplete,
	}
	for in, want := range cases {
		if got := ResultType(json.RawMessage(in)); got != want {
			t.Errorf("ResultType(%q) = %q, want %q", in, got, want)
		}
	}
}

// A server that needs client input mid-call returns input_required rather
// than issuing its own request. passmcp surfaces it instead of answering:
// there is no user to elicit from and no model to sample.
func TestInputRequiredIsSurfaced(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required","inputRequests":{"r1":{"method":"elicitation/create","params":{"message":"which account?"}}},"requestState":"opaque"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	s := New(srv.URL, srv.Client())
	s.SetDialect(&Stateless{ProtocolVersion: V20260728})
	var out map[string]any
	err := s.Call(context.Background(), "tools/call", map[string]any{"name": "t"}, &out)

	var ir *ErrInputRequired
	if !errors.As(err, &ir) {
		t.Fatalf("want ErrInputRequired, got %v", err)
	}
	if len(ir.Result.InputRequests) != 1 || ir.Result.InputRequests[0].Method != "elicitation/create" ||
		ir.Result.InputRequests[0].ID != "r1" {
		t.Errorf("input requests = %+v; the id should come from the key", ir.Result.InputRequests)
	}
	if ir.Result.RequestState != "opaque" || ir.Result.ListForm {
		t.Errorf("requestState %q, listForm %v", ir.Result.RequestState, ir.Result.ListForm)
	}
	if !strings.Contains(ir.Error(), "elicitation/create") {
		t.Errorf("the message should name what was asked for: %s", ir.Error())
	}
	if !strings.Contains(ir.Error(), "tools/call") {
		t.Errorf("the message should name the call: %s", ir.Error())
	}
}

func TestAsInputRequired(t *testing.T) {
	if _, ok := AsInputRequired("x", json.RawMessage(`{"resultType":"complete"}`)); ok {
		t.Error("a complete result is not an input request")
	}
	if _, ok := AsInputRequired("x", json.RawMessage(`{"resultType":"input_required","inputRequests":"bad"}`)); ok {
		t.Error("an undecodable input_required body must not be claimed")
	}
	if _, ok := AsInputRequired("x", json.RawMessage(`{"resultType":"input_required","inputRequests":{}}`)); !ok {
		t.Error("a well-formed input_required must be recognised")
	}
	// Only requestState: the specification requires at least one of the two.
	ir, ok := AsInputRequired("x", json.RawMessage(`{"resultType":"input_required","requestState":"s"}`))
	if !ok || len(ir.Result.InputRequests) != 0 || ir.Result.RequestState != "s" {
		t.Errorf("a state-only result: %+v %v", ir, ok)
	}
}

// TestInputRequestsAreSortedByKey, so two runs against one server report
// the same order.
func TestInputRequestsAreSortedByKey(t *testing.T) {
	ir, ok := AsInputRequired("x", json.RawMessage(`{"resultType":"input_required","inputRequests":{"b":{"method":"roots/list"},"a":{"method":"sampling/createMessage"}}}`))
	if !ok || len(ir.Result.InputRequests) != 2 || ir.Result.InputRequests[0].ID != "a" || ir.Result.InputRequests[1].ID != "b" {
		t.Fatalf("got %+v", ir)
	}
}

// TestTheListFormIsReadAndFlagged. No revision defines an array here, but
// servers send one; it is read so a report can say what was asked, and
// flagged so it can say the shape is wrong.
func TestTheListFormIsReadAndFlagged(t *testing.T) {
	ir, ok := AsInputRequired("x", json.RawMessage(`{"resultType":"input_required","inputRequests":[{"id":"r1","method":"elicitation/create"}]}`))
	if !ok || !ir.Result.ListForm || len(ir.Result.InputRequests) != 1 || ir.Result.InputRequests[0].ID != "r1" {
		t.Fatalf("got %+v %v", ir, ok)
	}
	if _, ok := AsInputRequired("x", json.RawMessage(`{"resultType":"input_required","inputRequests":[1,2]}`)); ok {
		t.Error("a list of non-objects was accepted")
	}
	if _, ok := AsInputRequired("x", json.RawMessage(`{"resultType":"input_required","inputRequests":{"a":7}}`)); ok {
		t.Error("an object of non-objects was accepted")
	}
}

func TestAsProtocolError(t *testing.T) {
	if AsProtocolError("v", nil) != nil {
		t.Error("nil in, nil out")
	}

	var uv *UnsupportedVersionError
	err := AsProtocolError(V20260728, &RPCError{Code: CodeUnsupportedProtocolVersion, Data: json.RawMessage(`{"supported":["2025-11-25"]}`)})
	if !errors.As(err, &uv) || len(uv.Supported) != 1 || uv.Requested != V20260728 {
		t.Fatalf("unsupported version: %+v", err)
	}
	if !strings.Contains(uv.Error(), "2025-11-25") {
		t.Errorf("the message must name what the server does support: %s", uv.Error())
	}

	var mc *MissingCapabilityError
	err = AsProtocolError("v", &RPCError{Code: CodeMissingClientCapability, Data: json.RawMessage(`{"requiredCapabilities":["elicitation"]}`)})
	if !errors.As(err, &mc) || len(mc.Required) != 1 {
		t.Fatalf("missing capability: %+v", err)
	}
	if !strings.Contains(mc.Error(), "elicitation") {
		t.Errorf("the message must name the capability: %s", mc.Error())
	}

	var hm *HeaderMismatchError
	err = AsProtocolError("v", &RPCError{Code: CodeHeaderMismatch, Message: "Mcp-Name mismatch"})
	if !errors.As(err, &hm) || !strings.Contains(hm.Error(), "Mcp-Name") {
		t.Fatalf("header mismatch: %+v", err)
	}

	// Anything else passes through untouched.
	plain := &RPCError{Code: -32601, Message: "no"}
	if got := AsProtocolError("v", plain); !errors.Is(got, plain) {
		t.Errorf("an ordinary RPC error must pass through: %v", got)
	}
	// Undecodable data must not lose the error type.
	err = AsProtocolError("v", &RPCError{Code: CodeUnsupportedProtocolVersion, Data: json.RawMessage(`"nope"`)})
	if !errors.As(err, &uv) {
		t.Errorf("a malformed data member must still yield the typed error: %v", err)
	}
}

// Telling a modern server from a legacy one turns on this: both answer 400,
// but only a modern one explains itself with a recognised JSON-RPC error.
func TestIsModernError(t *testing.T) {
	modern := []string{
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32020,"message":"x"}}`,
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32021,"message":"x"}}`,
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"x"}}`,
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"x"}}`,
	}
	for _, b := range modern {
		if _, ok := IsModernError([]byte(b)); !ok {
			t.Errorf("should be recognised as modern: %s", b)
		}
	}
	legacy := []string{
		``,
		`<html>Bad Request</html>`,
		`{"jsonrpc":"2.0","id":1,"result":{}}`,
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"invalid"}}`,
	}
	for _, b := range legacy {
		if _, ok := IsModernError([]byte(b)); ok {
			t.Errorf("should not be recognised as modern: %q", b)
		}
	}
}

func TestHTTPStatusErrorModern(t *testing.T) {
	plain := &HTTPStatusError{StatusCode: 400}
	if plain.Modern() || !strings.Contains(plain.Error(), "400") {
		t.Errorf("plain: %v", plain)
	}
	withErr := &HTTPStatusError{StatusCode: 400, RPCError: &RPCError{Code: CodeHeaderMismatch, Message: "x"}}
	if !withErr.Modern() || !strings.Contains(withErr.Error(), "jsonrpc error") {
		t.Errorf("modern: %v", withErr)
	}
}

func TestEncodeHeaderValue(t *testing.T) {
	safe := []string{"", "get_weather", "file:///a/b.json", "a-b_c.d", "with space inside"}
	for _, v := range safe {
		if got := EncodeHeaderValue(v); got != v {
			t.Errorf("EncodeHeaderValue(%q) = %q, want unchanged", v, got)
		}
	}
	unsafe := []string{
		"Hello, 世界",    // non-ASCII
		" padded ",     // leading and trailing space
		"line1\nline2", // control character
		"trailing\t",   // trailing tab
		"=?base64?x?=", // would be mistaken for the sentinel
		"\x00null",     // NUL
	}
	for _, v := range unsafe {
		enc := EncodeHeaderValue(v)
		if enc == v {
			t.Errorf("EncodeHeaderValue(%q) must encode", v)
			continue
		}
		if !strings.HasPrefix(enc, "=?base64?") || !strings.HasSuffix(enc, "?=") {
			t.Errorf("EncodeHeaderValue(%q) = %q, not in sentinel form", v, enc)
		}
		got, ok := DecodeHeaderValue(enc)
		if !ok || got != v {
			t.Errorf("round trip %q: got %q ok=%v", v, got, ok)
		}
	}
	// A value that only looks like the sentinel but does not decode is
	// reported rather than silently returned as-is.
	if _, ok := DecodeHeaderValue("=?base64?!!!not-base64!!!?="); ok {
		t.Error("an undecodable sentinel must be reported")
	}
	if got, ok := DecodeHeaderValue("plain"); !ok || got != "plain" {
		t.Errorf("a plain value passes through: %q %v", got, ok)
	}
}

func TestTargetNameEdgeCases(t *testing.T) {
	d := &Stateless{ProtocolVersion: V20260728}
	h := http.Header{}

	// A method that takes no name.
	if err := d.PrepareHeaders(h, &Request{Method: "tools/list"}); err != nil {
		t.Fatal(err)
	}
	if h.Get(HeaderName) != "" {
		t.Errorf("tools/list must not set %s", HeaderName)
	}
	// A name of the wrong type is a caller error, not something to mirror.
	err := d.PrepareHeaders(http.Header{}, &Request{Method: "tools/call", Params: json.RawMessage(`{"name":42}`)})
	if err == nil {
		t.Error("a non-string name must be refused")
	}
	// Params that do not parse, or lack the field, simply yield no header.
	for _, params := range []string{`not json`, `{}`, `{"other":"x"}`} {
		h := http.Header{}
		if err := d.PrepareHeaders(h, &Request{Method: "tools/call", Params: json.RawMessage(params)}); err != nil {
			t.Errorf("params %q: %v", params, err)
		}
		if h.Get(HeaderName) != "" {
			t.Errorf("params %q set %s", params, HeaderName)
		}
	}
	// A nil request still gets the version header.
	h2 := http.Header{}
	if err := d.PrepareHeaders(h2, nil); err != nil || h2.Get(HeaderProtocolVersion) != V20260728 {
		t.Errorf("nil request: %v %q", err, h2.Get(HeaderProtocolVersion))
	}
	if err := d.PrepareBody(nil); err != nil {
		t.Errorf("PrepareBody(nil): %v", err)
	}
	// A default-constructed Stateless still reports the current version.
	if v := (&Stateless{}).Version(); v != V20260728 {
		t.Errorf("default Version() = %q", v)
	}
}

// Existing _meta keys, such as a progress token, must survive the injection.
func TestPrepareBodyPreservesExistingMeta(t *testing.T) {
	d := &Stateless{ProtocolVersion: V20260728}
	rpc := &Request{Method: "tools/call", Params: json.RawMessage(`{"name":"t","_meta":{"progressToken":"p1"}}`)}
	if err := d.PrepareBody(rpc); err != nil {
		t.Fatal(err)
	}
	var params struct {
		Name string         `json:"name"`
		Meta map[string]any `json:"_meta"`
	}
	if err := json.Unmarshal(rpc.Params, &params); err != nil {
		t.Fatal(err)
	}
	if params.Name != "t" {
		t.Errorf("params.name was lost: %s", rpc.Params)
	}
	if params.Meta["progressToken"] != "p1" {
		t.Errorf("an existing _meta key was lost: %v", params.Meta)
	}
	if params.Meta[MetaProtocolVersion] != V20260728 {
		t.Errorf("protocol version not injected: %v", params.Meta)
	}
	// A _meta that is not an object is replaced rather than crashing.
	rpc2 := &Request{Method: "tools/list", Params: json.RawMessage(`{"_meta":"nonsense"}`)}
	if err := d.PrepareBody(rpc2); err != nil {
		t.Fatal(err)
	}
	// LogLevel is carried when set.
	d3 := &Stateless{ProtocolVersion: V20260728, LogLevel: "debug"}
	rpc3 := &Request{Method: "tools/list"}
	if err := d3.PrepareBody(rpc3); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rpc3.Params), "logLevel") {
		t.Errorf("log level not carried: %s", rpc3.Params)
	}
}

func TestSessionedFallbackVersion(t *testing.T) {
	// With no live state, the static version is used.
	d := &Sessioned{ProtocolVersion: V20250326}
	h := http.Header{}
	if err := d.PrepareHeaders(h, nil); err != nil {
		t.Fatal(err)
	}
	if h.Get(HeaderProtocolVersion) != V20250326 {
		t.Errorf("static version not used: %q", h.Get(HeaderProtocolVersion))
	}
	// An empty version sets no header at all, which is what a client does
	// before the handshake has settled one.
	empty := &Sessioned{}
	h2 := http.Header{}
	if err := empty.PrepareHeaders(h2, nil); err != nil {
		t.Fatal(err)
	}
	if h2.Get(HeaderProtocolVersion) != "" {
		t.Errorf("an unnegotiated dialect must send no version: %q", h2.Get(HeaderProtocolVersion))
	}
	if err := empty.PrepareBody(&Request{}); err != nil {
		t.Errorf("PrepareBody: %v", err)
	}
	// SetDialect(nil) restores the default binding.
	s := New("https://x/mcp", nil)
	s.SetDialect(nil)
	if !s.Dialect().Stateful() {
		t.Error("the default binding is session-based")
	}
}

// TestPrepareBodyKeepsPerRequestCapabilities. On the stateless revision a
// client declares capabilities per request, so one call may declare an
// extension the others do not; the dialect's default must not overwrite it.
func TestPrepareBodyKeepsPerRequestCapabilities(t *testing.T) {
	d := &Stateless{ProtocolVersion: V20260728, Capabilities: json.RawMessage(`{"sampling":{}}`)}
	declared := `{"extensions":{"io.modelcontextprotocol/tasks":{}}}`
	rpc := &Request{Method: "tools/call", Params: json.RawMessage(`{"name":"t","_meta":{"` + MetaClientCapabilities + `":` + declared + `}}`)}
	if err := d.PrepareBody(rpc); err != nil {
		t.Fatal(err)
	}
	var params struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if err := json.Unmarshal(rpc.Params, &params); err != nil {
		t.Fatal(err)
	}
	if got := string(params.Meta[MetaClientCapabilities]); got != declared {
		t.Errorf("per-request capabilities were replaced: %s", got)
	}

	// Without one, the dialect's own declaration applies.
	plain := &Request{Method: "tools/list", Params: json.RawMessage(`{}`)}
	if err := d.PrepareBody(plain); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(plain.Params, &params); err != nil {
		t.Fatal(err)
	}
	if got := string(params.Meta[MetaClientCapabilities]); got != `{"sampling":{}}` {
		t.Errorf("default capabilities = %s", got)
	}
}
