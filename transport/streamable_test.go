// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCallJSONAndSessionHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req Request
		json.NewDecoder(r.Body).Decode(&req)
		switch req.Method {
		case "initialize":
			w.Header().Set(HeaderSessionID, "sess-1")
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{"protocolVersion":"2025-11-25"}}`, *req.ID)
		case "notifications/initialized":
			if r.Header.Get(HeaderSessionID) != "sess-1" || r.Header.Get(HeaderProtocolVersion) != "2025-11-25" {
				t.Errorf("headers not propagated: %v", r.Header)
			}
			w.WriteHeader(202)
		case "ping":
			if r.Header.Get("Accept") != "application/json, text/event-stream" {
				t.Errorf("accept = %q", r.Header.Get("Accept"))
			}
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{}}`, *req.ID)
		case "boom":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"error":{"code":-32601,"message":"nope"}}`, *req.ID)
		}
	}))
	defer srv.Close()
	s := New(srv.URL, srv.Client())
	var res struct{ ProtocolVersion string }
	if err := s.Call(context.Background(), "initialize", map[string]any{}, &res); err != nil {
		t.Fatal(err)
	}
	s.SetProtocolVersion(res.ProtocolVersion)
	if s.SessionID() != "sess-1" {
		t.Errorf("session = %q", s.SessionID())
	}
	if err := s.Notify(context.Background(), "notifications/initialized", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Call(context.Background(), "ping", nil, nil); err != nil {
		t.Fatal(err)
	}
	err := s.Call(context.Background(), "boom", nil, nil)
	var rpc *RPCError
	if !errors.As(err, &rpc) || rpc.Code != -32601 {
		t.Errorf("err = %v", err)
	}
}

func TestCallSSEResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req Request
		json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, ": keepalive\n\n")
		fmt.Fprint(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n")
		fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":%d,\ndata: \"result\":{\"answer\":42}}\n\n", *req.ID)
	}))
	defer srv.Close()
	s := New(srv.URL, srv.Client())
	var res struct{ Answer int }
	if err := s.Call(context.Background(), "x", nil, &res); err != nil {
		t.Fatal(err)
	}
	if res.Answer != 42 {
		t.Errorf("res = %+v", res)
	}
}

func TestSessionExpiryAnd401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(HeaderSessionID) == "gone" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="https://x/prm"`)
		w.WriteHeader(401)
	}))
	defer srv.Close()
	s := New(srv.URL, srv.Client())
	s.SetSessionID("gone")
	if err := s.Call(context.Background(), "ping", nil, nil); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("err = %v", err)
	}
	if s.SessionID() != "" {
		t.Error("session not reset")
	}
	err := s.Call(context.Background(), "ping", nil, nil)
	var he *HTTPStatusError
	if !errors.As(err, &he) || he.StatusCode != 401 || he.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("err = %v", err)
	}
}
