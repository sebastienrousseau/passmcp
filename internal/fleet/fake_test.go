// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package fleet

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeTool is one tool the fake server lists.
type fakeTool struct {
	Name        string
	Description string
	ReadOnly    *bool
}

// fakeServer is a minimal MCP server whose catalogue a test can change
// between two fleet runs.
type fakeServer struct {
	mu    sync.Mutex
	srv   *httptest.Server
	tools []fakeTool
	// token, when set, is required as a bearer token.
	token string
	// echo puts the presented token into every description and result, the
	// way a careless server reflects a credential back.
	echo  bool
	hosts map[string]int
}

func newFake(t *testing.T, tools ...fakeTool) *fakeServer {
	t.Helper()
	f := &fakeServer{tools: tools, hosts: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeServer) setTools(tools ...fakeTool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tools = tools
}

func boolp(b bool) *bool { return &b }

func (f *fakeServer) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.hosts[r.Host]++
	tools, token, echo := append([]fakeTool(nil), f.tools...), f.token, f.echo
	f.mu.Unlock()
	if r.URL.Path != "/mcp" {
		http.NotFound(w, r)
		return
	}
	presented := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token != "" && presented != token {
		w.Header().Set("WWW-Authenticate", `Bearer realm="fake"`)
		http.Error(w, "unauthorised", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	b, _ := io.ReadAll(r.Body)
	if json.Unmarshal(b, &req) != nil {
		writeRPC(w, nil, nil, &rpcErr{-32700, "parse error"})
		return
	}
	if len(req.ID) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	suffix := ""
	if echo {
		suffix = " (authorised as " + presented + ")"
	}
	switch req.Method {
	case "initialize":
		w.Header().Set("Mcp-Session-Id", "fake-session")
		writeRPC(w, req.ID, map[string]any{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "fake", "version": "1.0.0"},
		}, nil)
	case "ping":
		writeRPC(w, req.ID, map[string]any{}, nil)
	case "tools/list":
		writeRPC(w, req.ID, map[string]any{"tools": listing(tools, suffix)}, nil)
	case "tools/call":
		writeRPC(w, req.ID, map[string]any{"content": []any{map[string]any{"type": "text", "text": "ok" + suffix}}}, nil)
	default:
		writeRPC(w, req.ID, nil, &rpcErr{-32601, "method not found"})
	}
}

func listing(tools []fakeTool, suffix string) []any {
	out := make([]any, 0, len(tools))
	for _, t := range tools {
		tool := map[string]any{
			"name":        t.Name,
			"description": t.Description + suffix,
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		}
		if t.ReadOnly != nil {
			tool["annotations"] = map[string]any{"readOnlyHint": *t.ReadOnly}
		}
		out = append(out, tool)
	}
	return out
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func writeRPC(w http.ResponseWriter, id json.RawMessage, result any, e *rpcErr) {
	w.Header().Set("Content-Type", "application/json")
	msg := map[string]any{"jsonrpc": "2.0", "id": id}
	if e != nil {
		msg["error"] = e
	} else {
		msg["result"] = result
	}
	_ = json.NewEncoder(w).Encode(msg)
}
