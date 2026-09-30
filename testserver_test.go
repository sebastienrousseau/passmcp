// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package passmcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"satellion.com/passmcp/transport"
)

// fakeStack is an MCP server plus an authorization server, both under one
// httptest.Server so relative discovery paths resolve.
type fakeStack struct {
	srv            *httptest.Server
	requireAuth    bool
	cimd           bool
	registrations  atomic.Int32
	tokenRequests  atomic.Int32
	lastTokenForm  url.Values
	tools          []Tool
	callsByTool    map[string]int
	sessionCounter atomic.Int32
	strictScope    string // tool calls need this scope in the token, else 403 insufficient_scope
	noChallenge    bool   // 401 without a WWW-Authenticate header
	protocolVer    string // protocol version to negotiate (default 2025-11-25)
	noRegistration bool   // omit registration_endpoint from AS metadata
	cursorCycle    bool   // tools/list cursors run page2 -> page3 -> page2, forever
}

func newFakeStack(t *testing.T) *fakeStack {
	t.Helper()
	f := &fakeStack{callsByTool: map[string]int{}}
	yes, no := true, false
	f.tools = []Tool{
		{Name: "get_time", Description: "Current time", InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
			OutputSchema: json.RawMessage(`{"type":"object","required":["iso"],"properties":{"iso":{"type":"string"}}}`),
			Annotations:  &ToolAnnotations{ReadOnlyHint: &yes}},
		{Name: "search", Description: "Search things", InputSchema: json.RawMessage(`{"type":"object","required":["q"],"properties":{"q":{"type":"string","minLength":2},"limit":{"type":"integer","minimum":1,"maximum":5}}}`),
			OutputSchema: json.RawMessage(`{"type":"object","required":["hits"],"properties":{"hits":{"type":"array","items":{"type":"string"}}}}`),
			Annotations:  &ToolAnnotations{ReadOnlyHint: &yes}},
		{Name: "delete_all", Description: "Danger", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "rename", Description: "Mutating but safe", InputSchema: json.RawMessage(`{"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}`),
			Annotations: &ToolAnnotations{ReadOnlyHint: &no, DestructiveHint: &no}},
	}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	base := f.srv.URL

	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"resource": base + "/mcp", "authorization_servers": []string{base + "/as"}, "scopes_supported": []string{"mcp:read", "mcp:write"}})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server/as", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": base + "/as", "authorization_endpoint": base + "/as/authorize", "token_endpoint": base + "/as/token",
			"registration_endpoint": regEndpoint(f, base), "code_challenge_methods_supported": []string{"S256"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
			"client_id_metadata_document_supported": f.cimd,
		})
	})
	mux.HandleFunc("/as/register", func(w http.ResponseWriter, r *http.Request) {
		f.registrations.Add(1)
		var md map[string]any
		json.NewDecoder(r.Body).Decode(&md)
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"client_id": "dyn-client", "client_secret": "dyn-secret", "client_name": md["client_name"]})
	})
	mux.HandleFunc("/as/token", func(w http.ResponseWriter, r *http.Request) {
		f.tokenRequests.Add(1)
		r.ParseForm()
		f.lastTokenForm = r.PostForm
		if r.PostForm.Get("resource") != base+"/mcp" {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_target", "error_description": "resource " + r.PostForm.Get("resource")})
			return
		}
		scope := r.PostForm.Get("scope")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at|" + scope, "token_type": "Bearer", "expires_in": 3600, "refresh_token": "rt", "scope": scope})
	})
	mux.HandleFunc("/mcp", f.handleMCP)
	return f
}

func (f *fakeStack) handleMCP(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if f.requireAuth && (tok == "" || tok == "bad-bearer") {
		if !f.noChallenge {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="mcp", resource_metadata="%s/.well-known/oauth-protected-resource/mcp", scope="mcp:read"`, f.srv.URL))
		}
		w.WriteHeader(401)
		return
	}
	var req transport.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		return
	}
	reply := func(result any) {
		b, _ := json.Marshal(result)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":%s}`, *req.ID, b)
	}
	switch req.Method {
	case "initialize":
		var p initializeParams
		json.Unmarshal(req.Params, &p)
		if p.ProtocolVersion == "" || p.ClientInfo.Name == "" {
			w.WriteHeader(400)
			return
		}
		w.Header().Set(transport.HeaderSessionID, fmt.Sprintf("s%d", f.sessionCounter.Add(1)))
		pv := f.protocolVer
		if pv == "" {
			pv = "2025-11-25"
		}
		reply(InitializeResult{ProtocolVersion: pv, ServerInfo: Implementation{Name: "fake", Version: "1"}})
	case "notifications/initialized":
		w.WriteHeader(202)
	case "ping":
		reply(map[string]any{})
	case "resources/list":
		var p cursorParams
		json.Unmarshal(req.Params, &p)
		if p.Cursor == "" {
			reply(map[string]any{"resources": []Resource{{URI: "fake://a", Name: "a"}}, "nextCursor": "r2"})
		} else {
			reply(map[string]any{"resources": []Resource{{URI: "fake://b", Name: "b"}}})
		}
	case "resources/templates/list":
		reply(map[string]any{"resourceTemplates": []ResourceTemplate{{URITemplate: "fake://{id}", Name: "t"}}})
	case "resources/read":
		reply(ReadResourceResult{Contents: []ResourceContents{{URI: "fake://a", Text: "hello"}}})
	case "prompts/list":
		reply(map[string]any{"prompts": []Prompt{{Name: "p", Arguments: []PromptArgument{{Name: "x", Required: true}}}}})
	case "prompts/get":
		var p struct {
			Name string            `json:"name"`
			Args map[string]string `json:"arguments"`
		}
		json.Unmarshal(req.Params, &p)
		reply(GetPromptResult{Description: p.Name, Messages: []PromptMessage{{Role: "user", Content: Content{Type: "text", Text: p.Args["x"]}}}})
	case "tools/list":
		var p listToolsParams
		json.Unmarshal(req.Params, &p)
		switch {
		case p.Cursor == "":
			reply(listToolsResult{Tools: f.tools[:2], NextCursor: "page2"})
		case f.cursorCycle && p.Cursor == "page2":
			reply(listToolsResult{Tools: f.tools[2:3], NextCursor: "page3"})
		case f.cursorCycle:
			reply(listToolsResult{Tools: f.tools[3:], NextCursor: "page2"})
		default:
			reply(listToolsResult{Tools: f.tools[2:]})
		}
	case "tools/call":
		if f.strictScope != "" && !strings.Contains(tok, f.strictScope) {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="insufficient_scope", scope="%s"`, f.strictScope))
			w.WriteHeader(403)
			return
		}
		var p struct {
			Name string         `json:"name"`
			Args map[string]any `json:"arguments"`
		}
		json.Unmarshal(req.Params, &p)
		f.callsByTool[p.Name]++
		switch p.Name {
		case "get_time":
			reply(CallToolResult{Content: []Content{{Type: "text", Text: "now"}}, StructuredContent: json.RawMessage(`{"iso":"2026-01-01T00:00:00Z"}`)})
		case "search":
			if q, _ := p.Args["q"].(string); len(q) < 2 {
				reply(CallToolResult{Content: []Content{{Type: "text", Text: "q too short"}}, IsError: true})
				return
			}
			// Deliberately violates outputSchema: hits is a string.
			reply(CallToolResult{Content: []Content{{Type: "text", Text: "ok"}}, StructuredContent: json.RawMessage(`{"hits":"oops"}`)})
		default:
			reply(CallToolResult{Content: []Content{{Type: "text", Text: "done"}}})
		}
	default:
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"error":{"code":-32601,"message":"method not found"}}`, *req.ID)
	}
}

func regEndpoint(f *fakeStack, base string) string {
	if f.noRegistration {
		return ""
	}
	return base + "/as/register"
}
