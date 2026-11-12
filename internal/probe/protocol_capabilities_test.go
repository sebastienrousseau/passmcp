// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/transport"
)

// A resources-only server answers -32601 to tools/call because it never
// claimed the tools capability. Before capability gating, protocol.unknown_tool
// read that -32601 as proof that unknown tools were rejected (a thin-shadow
// pass violating ADR-0002), and protocol.invalid_params reported info instead
// of skipping.
func TestProtocolSkipsToolsProbesWhenToolsNotDeclared(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				URI string `json:"uri"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"resources":{}},"serverInfo":{"name":"res-only","version":"1.0"}}}`, req.ID)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "ping":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{}}`, req.ID)
		case "resources/read":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32602,"message":"Resource not found","data":{"uri":%q}}}`, req.ID, req.Params.URI)
		default:
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"Method not found"}}`, req.ID)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s, err := Run(ctx, Options{
		Endpoint: srv.URL, HTTPClient: srv.Client(), Version: "test",
		Creds: &creds.Credentials{Mode: creds.ModeNone},
		Only:  []string{"handshake", "protocol"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, id := range []string{"protocol.invalid_params", "protocol.unknown_tool"} {
		f, ok := findingByID(s, id)
		if !ok {
			t.Fatalf("missing %s", id)
		}
		if f.Status != Skip || !strings.Contains(f.Detail, "does not declare the tools capability") {
			t.Errorf("%s = %s (%q), want skip naming undeclared tools capability", id, f.Status, f.Detail)
		}
	}
	f, ok := findingByID(s, "protocol.unknown_resource")
	if !ok {
		t.Fatal("missing protocol.unknown_resource")
	}
	if f.Status != Pass {
		t.Errorf("protocol.unknown_resource = %s (%q), want pass", f.Status, f.Detail)
	}
	if len(f.Evidence) == 0 {
		t.Error("protocol.unknown_resource passed without citing evidence")
	}
}

// TestProtocolCapabilitySkipWithoutHandshakeOrDiscover covers the two runs
// where declared capabilities were never learned.
func TestProtocolCapabilitySkipWithoutHandshakeOrDiscover(t *testing.T) {
	// 1. Stateless server omitting server/discover.
	s := runStateless(t, statelessFake(t, statelessOpts{noDiscover: true}), func(o *Options) {
		o.Only = []string{"discovery", "handshake", "protocol"}
	})
	for _, id := range []string{"protocol.invalid_params", "protocol.unknown_tool", "protocol.unknown_resource"} {
		f, ok := findingByID(s, id)
		if !ok || f.Status != Skip || !strings.Contains(f.Detail, "server/discover") {
			t.Errorf("noDiscover %s = %+v, want skip citing server/discover", id, f)
		}
	}

	// 2. --only protocol (s.Init == nil).
	fSrv := newFakeServer(t)
	fSrv.q.open = true
	s2, fs := run(t, fSrv, &creds.Credentials{Mode: creds.ModeNone}, func(o *Options) {
		o.Only = []string{"protocol"}
	})
	_ = s2
	for _, id := range []string{"protocol.invalid_params", "protocol.unknown_tool", "protocol.unknown_resource"} {
		f, ok := fs[id]
		if !ok || f.Status != Skip || !strings.Contains(f.Detail, "handshake did not run") {
			t.Errorf("only-protocol %s = %+v, want skip citing handshake", id, f)
		}
	}
}

// TestProtocolUnknownResourceSEP2164 verifies SEP-2164 behaviour on both
// stateless (2026-07-28) and handshake revisions.
func TestProtocolUnknownResourceSEP2164(t *testing.T) {
	// Tools-only stateless server skips protocol.unknown_resource.
	sSkip := runStateless(t, statelessFake(t, statelessOpts{}), func(o *Options) {
		o.Only = []string{"discovery", "handshake", "protocol"}
	})
	if f, ok := findingByID(sSkip, "protocol.unknown_resource"); !ok || f.Status != Skip {
		t.Fatalf("tools-only stateless server: protocol.unknown_resource = %+v, want skip", f)
	}

	cases := []struct {
		name      string
		stateless bool
		replyFn   func(id json.RawMessage, uri string) string
		want      Status
		substr    string
	}{
		{
			name:      "stateless-32602-with-data-uri",
			stateless: true,
			replyFn: func(id json.RawMessage, uri string) string {
				return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32602,"message":"Resource not found","data":{"uri":%q}}}`, id, uri)
			},
			want:   Pass,
			substr: "data.uri",
		},
		{
			name:      "stateless-32602-missing-data-uri",
			stateless: true,
			replyFn: func(id json.RawMessage, _ string) string {
				return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32602,"message":"Resource not found"}}`, id)
			},
			want:   Warn,
			substr: "data.uri",
		},
		{
			name:      "stateless-retired-32002",
			stateless: true,
			replyFn: func(id json.RawMessage, uri string) string {
				return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32002,"message":"Resource not found","data":{"uri":%q}}}`, id, uri)
			},
			want:   Warn,
			substr: "-32002",
		},
		{
			name:      "stateless-other-rpc-error",
			stateless: true,
			replyFn: func(id json.RawMessage, _ string) string {
				return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32603,"message":"boom"}}`, id)
			},
			want:   Warn,
			substr: "-32602 expected",
		},
		{
			name:      "stateless-success-is-major-failure",
			stateless: true,
			replyFn: func(id json.RawMessage, uri string) string {
				return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","contents":[{"uri":%q,"text":"ghost"}]}}`, id, uri)
			},
			want:   Fail,
			substr: "non-existent resource",
		},
		{
			name:      "session-32002-passes",
			stateless: false,
			replyFn: func(id json.RawMessage, _ string) string {
				return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32002,"message":"Resource not found"}}`, id)
			},
			want:   Pass,
			substr: "-32002",
		},
		{
			name:      "session-other-rpc-error-warns",
			stateless: false,
			replyFn: func(id json.RawMessage, _ string) string {
				return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32603,"message":"boom"}}`, id)
			},
			want:   Warn,
			substr: "-32002 or -32602 expected",
		},
		{
			name:      "session-success-fails",
			stateless: false,
			replyFn: func(id json.RawMessage, uri string) string {
				return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"contents":[{"uri":%q,"text":"ghost"}]}}`, id, uri)
			},
			want:   Fail,
			substr: "non-existent resource",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := resourceProbeServer(t, tc.stateless, tc.replyFn)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			s, err := Run(ctx, Options{
				Endpoint: srv.URL, HTTPClient: srv.Client(), Version: "test",
				Creds: &creds.Credentials{Mode: creds.ModeNone},
				Only:  []string{"discovery", "handshake", "protocol"},
			})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			f, ok := findingByID(s, "protocol.unknown_resource")
			if !ok {
				t.Fatal("missing protocol.unknown_resource")
			}
			if f.Status != tc.want || !strings.Contains(f.Detail, tc.substr) {
				t.Errorf("got %s (%q), want %s containing %q", f.Status, f.Detail, tc.want, tc.substr)
			}
		})
	}
}

func resourceProbeServer(t *testing.T, stateless bool, readReply func(id json.RawMessage, uri string) string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				URI string `json:"uri"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if stateless {
			if h := r.Header.Get(transport.HeaderMethod); h != "" && h != req.Method {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":"mismatch"}}`, req.ID, transport.CodeHeaderMismatch)
				return
			}
			switch req.Method {
			case "server/discover":
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","serverInfo":{"name":"res-srv","version":"1.0"},"capabilities":{"resources":{}}}}`, req.ID)
			case "resources/list":
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","resources":[],"ttlMs":0,"cacheScope":"private"}}`, req.ID)
			case "resources/read":
				_, _ = w.Write([]byte(readReply(req.ID, req.Params.URI)))
			default:
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"not found"}}`, req.ID)
			}
			return
		}
		switch req.Method {
		case "initialize":
			if r.Header.Get("Mcp-Protocol-Version") == "" && req.Method == "initialize" {
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"resources":{}},"serverInfo":{"name":"res-srv","version":"1.0"}}}`, req.ID)
				return
			}
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"resources":{}},"serverInfo":{"name":"res-srv","version":"1.0"}}}`, req.ID)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "ping":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{}}`, req.ID)
		case "resources/read":
			_, _ = w.Write([]byte(readReply(req.ID, req.Params.URI)))
		default:
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"not found"}}`, req.ID)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}
