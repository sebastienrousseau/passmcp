// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package discover

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeMCP is a local MCP server with knobs for each shape discovery must
// tell apart. Every test that needs a server uses one; none touches the
// network beyond 127.0.0.1.
type fakeMCP struct {
	// path is where the endpoint is mounted.
	path string
	// auth answers every RPC with 401 and a resource_metadata challenge.
	auth bool
	// stateless refuses initialize and answers server/discover instead.
	stateless bool
	// sse answers with an event stream rather than JSON.
	sse bool
	// hideTools answers tools/list with an error, as a server that
	// requires credentials beyond the handshake would.
	hideTools bool
	// card is served at /.well-known/mcp when non-nil.
	card any
	// redirect sends /mcp elsewhere when set.
	redirect string
	// delay holds every request, to observe concurrency.
	delay time.Duration

	hits     atomic.Int64
	inFlight atomic.Int64
	maxIn    atomic.Int64
	mu       sync.Mutex
	methods  []string
	srv      *httptest.Server
}

// start serves the fake and stops it with the test.
func (f *fakeMCP) start(t *testing.T) *fakeMCP {
	t.Helper()
	if f.path == "" {
		f.path = "/mcp"
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// url is the server's base URL.
func (f *fakeMCP) url() string { return f.srv.URL }

// called lists the JSON-RPC methods the fake received.
func (f *fakeMCP) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.methods...)
}

func (f *fakeMCP) serve(w http.ResponseWriter, r *http.Request) {
	f.hits.Add(1)
	n := f.inFlight.Add(1)
	defer f.inFlight.Add(-1)
	for {
		m := f.maxIn.Load()
		if n <= m || f.maxIn.CompareAndSwap(m, n) {
			break
		}
	}
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	switch {
	case r.URL.Path == "/.well-known/mcp" && f.card != nil:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(f.card)
	case f.redirect != "" && r.URL.Path == "/mcp":
		http.Redirect(w, r, f.redirect, http.StatusFound)
	case r.URL.Path == f.path && r.Method == http.MethodPost:
		f.rpc(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeMCP) rpc(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     *int64 `json:"id"`
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	b, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(b, &req)
	f.mu.Lock()
	f.methods = append(f.methods, req.Method)
	if req.Method == "tools/call" {
		f.methods = append(f.methods, "tools/call:"+req.Params.Name)
	}
	f.mu.Unlock()
	if f.auth {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+f.srv.URL+`/.well-known/oauth-protected-resource"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if req.ID == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	result, rpcErr := f.answer(req.Method)
	msg := map[string]any{"jsonrpc": "2.0", "id": *req.ID}
	if rpcErr != "" {
		msg["error"] = map[string]any{"code": -32601, "message": rpcErr}
	} else {
		msg["result"] = result
	}
	body, _ := json.Marshal(msg)
	if req.Method == "initialize" {
		w.Header().Set("Mcp-Session-Id", "sess-1")
	}
	if f.sse {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", body)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// answer is the result, or the error message, for a method.
func (f *fakeMCP) answer(method string) (any, string) {
	switch method {
	case "initialize":
		if f.stateless {
			return nil, "Method not found"
		}
		return map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{"tools": map[string]any{}},
			"serverInfo": map[string]any{"name": "fake-mcp", "version": "1.2.3"}}, ""
	case "server/discover":
		if !f.stateless {
			return nil, "Method not found"
		}
		return map[string]any{"supportedVersions": []string{"2026-07-28"},
			"_meta": map[string]any{"io.modelcontextprotocol/serverInfo": map[string]any{"name": "stateless-mcp", "version": "2"}}}, ""
	case "tools/list":
		if f.hideTools {
			return nil, "Unauthorized"
		}
		return map[string]any{"tools": []any{
			map[string]any{"name": "read_notes", "annotations": map[string]any{"readOnlyHint": true}, "inputSchema": map[string]any{"type": "object"}},
			map[string]any{"name": "delete_everything", "annotations": map[string]any{"destructiveHint": true}, "inputSchema": map[string]any{"type": "object"}},
		}}, ""
	case "tools/call":
		return map[string]any{"content": []any{map[string]any{"type": "text", "text": "ok"}}}, ""
	case "ping":
		return map[string]any{}, ""
	}
	return nil, "Method not found"
}

// fakeCounter tracks requests in flight across several fakes.
type fakeCounter struct {
	in  atomic.Int64
	top atomic.Int64
}

// wrap counts requests through h.
func (c *fakeCounter) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := c.in.Add(1)
		defer c.in.Add(-1)
		for {
			m := c.top.Load()
			if n <= m || c.top.CompareAndSwap(m, n) {
				break
			}
		}
		h.ServeHTTP(w, r)
	})
}

func (c *fakeCounter) max() int64 { return c.top.Load() }
func (c *fakeCounter) reset()     { c.top.Store(0) }

// newFakeRegistry serves the official registry's v0 list shape across two
// pages, with a server from another publisher among the results, as the
// real search's substring match returns.
func newFakeRegistry(t *testing.T) *httptest.Server {
	t.Helper()
	entry := func(name, u string) map[string]any {
		return map[string]any{"server": map[string]any{"name": name, "remotes": []any{map[string]any{"type": "streamable-http", "url": u}}}}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v0/servers" || r.URL.Query().Get("search") == "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("cursor") == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"servers":  []any{entry("io.github.acme/notes", "https://acme.example/mcp"), entry("io.github.acmecorp/other", "https://other.example/mcp")},
				"metadata": map[string]any{"nextCursor": "page2"},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"servers":  []any{entry("io.github.acme/crm", "https://acme2.example/mcp")},
			"metadata": map[string]any{},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}
