// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// captured is what a fake server saw on one request.
type captured struct {
	header http.Header
	body   map[string]any
}

func captureServer(t *testing.T, reply string) (*httptest.Server, *captured) {
	t.Helper()
	got := &captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.header = r.Header.Clone()
		_ = json.NewDecoder(r.Body).Decode(&got.body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func meta(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	params, ok := body["params"].(map[string]any)
	if !ok {
		t.Fatalf("params is not an object: %#v", body["params"])
	}
	m, ok := params["_meta"].(map[string]any)
	if !ok {
		t.Fatalf("params._meta is not an object: %#v", params)
	}
	return m
}

// The 2026-07-28 revision requires protocolVersion and clientCapabilities
// in every request's _meta; a request without them is malformed and the
// server must reject it with -32602.
func TestStatelessCarriesRequiredMeta(t *testing.T) {
	srv, got := captureServer(t, `{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete"}}`)
	s := New(srv.URL, srv.Client())
	s.SetDialect(&Stateless{
		ProtocolVersion: V20260728,
		ClientInfo:      Implementation{Name: "passmcp", Version: "1.2.3"},
	})
	if err := s.Call(context.Background(), "tools/list", map[string]any{}, nil); err != nil {
		t.Fatal(err)
	}

	m := meta(t, got.body)
	if m[MetaProtocolVersion] != V20260728 {
		t.Errorf("%s = %v", MetaProtocolVersion, m[MetaProtocolVersion])
	}
	if _, ok := m[MetaClientCapabilities]; !ok {
		t.Errorf("%s is required on every request: %#v", MetaClientCapabilities, m)
	}
	ci, ok := m[MetaClientInfo].(map[string]any)
	if !ok || ci["name"] != "passmcp" || ci["version"] != "1.2.3" {
		t.Errorf("%s = %#v", MetaClientInfo, m[MetaClientInfo])
	}
	// The header must agree with the body, or the server answers -32020.
	if h := got.header.Get(HeaderProtocolVersion); h != V20260728 {
		t.Errorf("%s header = %q", HeaderProtocolVersion, h)
	}
	if h := got.header.Get(HeaderMethod); h != "tools/list" {
		t.Errorf("%s = %q, want tools/list", HeaderMethod, h)
	}
	// Sessions are gone; nothing may claim one.
	if h := got.header.Get(HeaderSessionID); h != "" {
		t.Errorf("a stateless request must not carry %s: %q", HeaderSessionID, h)
	}
}

// Mcp-Name mirrors params.name for tools/call and prompts/get, and
// params.uri for resources/read. It is required for those three.
func TestStatelessMirrorsTargetName(t *testing.T) {
	cases := []struct {
		method, want string
		params       map[string]any
	}{
		{"tools/call", "get_weather", map[string]any{"name": "get_weather", "arguments": map[string]any{"city": "Paris"}}},
		{"prompts/get", "summarise", map[string]any{"name": "summarise"}},
		{"resources/read", "file:///a/b.json", map[string]any{"uri": "file:///a/b.json"}},
		{"tasks/get", "786512e2-9e0d", map[string]any{"taskId": "786512e2-9e0d"}},
		{"tasks/update", "786512e2-9e0d", map[string]any{"taskId": "786512e2-9e0d", "inputResponses": map[string]any{}}},
		{"tasks/cancel", "786512e2-9e0d", map[string]any{"taskId": "786512e2-9e0d"}},
		{"tools/list", "", map[string]any{}},
	}
	for _, c := range cases {
		t.Run(c.method, func(t *testing.T) {
			srv, got := captureServer(t, `{"jsonrpc":"2.0","id":1,"result":{}}`)
			s := New(srv.URL, srv.Client())
			s.SetDialect(&Stateless{ProtocolVersion: V20260728})
			if err := s.Call(context.Background(), c.method, c.params, nil); err != nil {
				t.Fatal(err)
			}
			if h := got.header.Get(HeaderName); h != c.want {
				t.Errorf("%s = %q, want %q", HeaderName, h, c.want)
			}
			if h := got.header.Get(HeaderMethod); h != c.method {
				t.Errorf("%s = %q", HeaderMethod, h)
			}
		})
	}
}

// A name outside the safe field-value set is carried in the Base64 sentinel
// form, so it cannot be smuggled into the header or split it.
func TestStatelessEncodesUnsafeName(t *testing.T) {
	srv, got := captureServer(t, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	s := New(srv.URL, srv.Client())
	s.SetDialect(&Stateless{ProtocolVersion: V20260728})
	const name = "tool with 世界"
	if err := s.Call(context.Background(), "tools/call", map[string]any{"name": name}, nil); err != nil {
		t.Fatal(err)
	}
	h := got.header.Get(HeaderName)
	if h == name {
		t.Fatal("a non-ASCII name must not be sent verbatim")
	}
	decoded, ok := DecodeHeaderValue(h)
	if !ok || decoded != name {
		t.Errorf("round trip: %q -> %q (ok=%v)", h, decoded, ok)
	}
	// The body remains the source of truth and is unencoded.
	params := got.body["params"].(map[string]any)
	if params["name"] != name {
		t.Errorf("body name = %v", params["name"])
	}
}

// The session-based dialects must behave exactly as before.
func TestSessionedIsUnchanged(t *testing.T) {
	srv, got := captureServer(t, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	s := New(srv.URL, srv.Client())
	s.SetProtocolVersion(V20251125)
	s.SetSessionID("sess-9")
	if err := s.Call(context.Background(), "tools/call", map[string]any{"name": "t"}, nil); err != nil {
		t.Fatal(err)
	}
	if h := got.header.Get(HeaderProtocolVersion); h != V20251125 {
		t.Errorf("%s = %q", HeaderProtocolVersion, h)
	}
	if h := got.header.Get(HeaderSessionID); h != "sess-9" {
		t.Errorf("%s = %q", HeaderSessionID, h)
	}
	// The routing headers and _meta belong to the newer revision only.
	if h := got.header.Get(HeaderMethod); h != "" {
		t.Errorf("a session-era request must not carry %s: %q", HeaderMethod, h)
	}
	if params, ok := got.body["params"].(map[string]any); ok {
		if _, ok := params["_meta"]; ok {
			t.Error("a session-era request must not inject _meta")
		}
	}
}

// Switching to a stateless dialect must drop session state, which can no
// longer mean anything.
func TestSetDialectClearsSession(t *testing.T) {
	s := New("https://x/mcp", nil)
	s.SetSessionID("sess-1")
	s.SetDialect(&Stateless{ProtocolVersion: V20260728})
	if s.SessionID() != "" {
		t.Errorf("session survived the switch: %q", s.SessionID())
	}
	if s.Dialect().Stateful() {
		t.Error("the stateless dialect must report Stateful() == false")
	}
	if s.ProtocolVersion() != V20260728 {
		t.Errorf("ProtocolVersion = %q", s.ProtocolVersion())
	}
}

// A 404 is session expiry only when the dialect has sessions at all. Under
// the stateless dialect it means "no such method".
func TestNotFoundIsNotSessionExpiryWhenStateless(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no such method"}}`))
	}))
	defer srv.Close()
	s := New(srv.URL, srv.Client())
	s.SetDialect(&Stateless{ProtocolVersion: V20260728})
	err := s.Call(context.Background(), "server/discover", map[string]any{}, nil)
	if errors.Is(err, ErrSessionExpired) {
		t.Fatal("a stateless dialect has no session to expire")
	}
	var he *HTTPStatusError
	if !errors.As(err, &he) || !he.Modern() || he.RPCError.Code != CodeMethodNotFound {
		t.Fatalf("want a modern method-not-found, got %v", err)
	}
}

func TestDialectFor(t *testing.T) {
	for _, v := range []string{V20260728} {
		d, err := DialectFor(v, Implementation{Name: "x"}, nil)
		if err != nil || d.Stateful() || d.Version() != v {
			t.Errorf("DialectFor(%q) = %v, %v", v, d, err)
		}
	}
	for _, v := range []string{V20251125, V20250618, V20250326, ""} {
		d, err := DialectFor(v, Implementation{}, nil)
		if err != nil || !d.Stateful() {
			t.Errorf("DialectFor(%q) = %v, %v", v, d, err)
		}
	}
	if _, err := DialectFor("1999-01-01", Implementation{}, nil); err == nil {
		t.Error("an unknown version must be an error")
	}
}

// Params that are not an object cannot carry _meta, and the specification
// models every request's params as one. Say so rather than dropping the
// required fields.
func TestStatelessRejectsNonObjectParams(t *testing.T) {
	s := New("https://x/mcp", nil)
	s.SetDialect(&Stateless{ProtocolVersion: V20260728})
	rpc := &Request{JSONRPC: "2.0", Method: "tools/list", Params: json.RawMessage(`["a"]`)}
	if err := s.Dialect().PrepareBody(rpc); err == nil {
		t.Fatal("array params must be refused")
	}
	// Absent params still get the required metadata.
	rpc2 := &Request{JSONRPC: "2.0", Method: "tools/list"}
	if err := s.Dialect().PrepareBody(rpc2); err != nil {
		t.Fatal(err)
	}
	var params map[string]any
	if err := json.Unmarshal(rpc2.Params, &params); err != nil {
		t.Fatal(err)
	}
	if _, ok := params["_meta"]; !ok {
		t.Errorf("_meta must be added even with no params: %s", rpc2.Params)
	}
}
