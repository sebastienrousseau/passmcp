// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"satellion.com/passmcp/transport"
)

// fakeServer is a protected MCP server with its own authorization server,
// enough to drive every subcommand end to end.
type fakeServer struct {
	srv      *httptest.Server
	mu       sync.Mutex
	sessions map[string]bool
	seq      atomic.Int32
	tokens   map[string]bool
	open     bool // accept requests without a token
	calls    map[string]int
	// personal adds a read-only customer lookup whose result carries a
	// name, an e-mail address and a phone number, for the masking tests.
	personal bool
	// agents records the User-Agent of every request, in order.
	agents []string
	// failReads answers resources/read and prompts/get with a JSON-RPC
	// error, as a server does for a URI or prompt it does not have.
	failReads bool
}

// Personal data the personal knob's tool returns. None of it may reach a
// report, a telemetry log or a HAR file.
const (
	fakeCustomerName  = "Ada Lovelace"
	fakeCustomerEmail = "ada.lovelace@example.org"
	fakeCustomerPhone = "+44 20 7946 0958"
)

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	f := &fakeServer{sessions: map[string]bool{}, tokens: map[string]bool{}, calls: map[string]int{}}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.agents = append(f.agents, r.Header.Get("User-Agent"))
		f.mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)
	base := f.srv.URL
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"resource": base + "/mcp", "authorization_servers": []string{base + "/as"}, "scopes_supported": []string{"mcp:read"}})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server/as", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": base + "/as", "authorization_endpoint": base + "/as/authorize", "token_endpoint": base + "/as/token",
			"registration_endpoint": base + "/as/register", "code_challenge_methods_supported": []string{"S256"}, "grant_types_supported": []string{"client_credentials", "authorization_code", "refresh_token"}})
	})
	mux.HandleFunc("/as/register", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "dyn", "client_secret": "dyn-secret-value"})
	})
	mux.HandleFunc("/as/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		tok := fmt.Sprintf("issued-token-%d", f.seq.Add(1))
		f.mu.Lock()
		f.tokens[tok] = true
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": 3600, "refresh_token": "rt-" + tok, "scope": r.PostForm.Get("scope")})
	})
	mux.HandleFunc("/mcp", f.handle)
	return f
}

func (f *fakeServer) validToken(r *http.Request) bool {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if f.open {
		return true
	}
	if tok == "" {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokens[tok]
}

func (f *fakeServer) handle(w http.ResponseWriter, r *http.Request) {
	req, ok := f.admit(w, r)
	if !ok {
		return
	}
	c := fakeRPC{w: w, id: req.ID}
	h, ok := fakeMethods[req.Method]
	if !ok {
		c.fail(-32601, "method not found")
		return
	}
	h(f, c, req)
}

// admit decodes a request the fake is willing to answer, or writes the
// HTTP status that refuses it.
func (f *fakeServer) admit(w http.ResponseWriter, r *http.Request) (transport.Request, bool) {
	var req transport.Request
	switch {
	case !f.validToken(r):
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource/mcp", scope="mcp:read"`, f.srv.URL))
		w.WriteHeader(401)
	case r.Method == http.MethodGet:
		w.WriteHeader(405)
	case json.NewDecoder(r.Body).Decode(&req) != nil:
		w.WriteHeader(400)
	case !f.knownSession(r.Header.Get(transport.HeaderSessionID)):
		w.WriteHeader(404)
	default:
		return req, true
	}
	return req, false
}

// knownSession reports whether sid is absent or one the fake issued.
func (f *fakeServer) knownSession(sid string) bool {
	if sid == "" {
		return true
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sessions[sid]
}

// fakeRPC writes the answer to one JSON-RPC request.
type fakeRPC struct {
	w  http.ResponseWriter
	id *int64
}

func (c fakeRPC) reply(v any) {
	b, _ := json.Marshal(v)
	c.w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(c.w, `{"jsonrpc":"2.0","id":%d,"result":%s}`, *c.id, b)
}

func (c fakeRPC) fail(code int, msg string) {
	c.w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(c.w, `{"jsonrpc":"2.0","id":%d,"error":{"code":%d,"message":%q}}`, *c.id, code, msg)
}

// fakeMethods are the JSON-RPC methods the fake answers.
var fakeMethods = map[string]func(*fakeServer, fakeRPC, transport.Request){
	"initialize":                (*fakeServer).initialize,
	"notifications/initialized": func(_ *fakeServer, c fakeRPC, _ transport.Request) { c.w.WriteHeader(202) },
	"ping":                      func(_ *fakeServer, c fakeRPC, _ transport.Request) { c.reply(map[string]any{}) },
	"tools/list":                (*fakeServer).listTools,
	"tools/call":                (*fakeServer).callTool,
	"resources/list": func(_ *fakeServer, c fakeRPC, _ transport.Request) {
		c.reply(map[string]any{"resources": []map[string]any{{"uri": "fake://doc/1", "name": "doc1", "mimeType": "text/plain"}}})
	},
	"resources/templates/list": func(_ *fakeServer, c fakeRPC, _ transport.Request) {
		c.reply(map[string]any{"resourceTemplates": []map[string]any{}})
	},
	"resources/read": (*fakeServer).serveRead,
	"prompts/get":    (*fakeServer).serveRead,
	"prompts/list": func(_ *fakeServer, c fakeRPC, _ transport.Request) {
		c.reply(map[string]any{"prompts": []map[string]any{{"name": "summarise", "description": "Summarise a doc", "arguments": []map[string]any{{"name": "doc", "description": "the doc", "required": true}}}}})
	},
}

func (f *fakeServer) initialize(c fakeRPC, _ transport.Request) {
	sid := fmt.Sprintf("sess-%d", f.seq.Add(1))
	f.mu.Lock()
	f.sessions[sid] = true
	f.mu.Unlock()
	c.w.Header().Set(transport.HeaderSessionID, sid)
	c.reply(map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{"tools": map[string]any{}, "resources": map[string]any{}, "prompts": map[string]any{}},
		"serverInfo": map[string]any{"name": "fake", "version": "1.0"}, "instructions": "Use wisely."})
}

func (f *fakeServer) listTools(c fakeRPC, _ transport.Request) {
	yes := true
	tools := []map[string]any{
		{"name": "get_time", "description": "Returns the current time in ISO 8601 format", "inputSchema": map[string]any{"type": "object"}, "outputSchema": map[string]any{"type": "object", "required": []string{"iso"}, "properties": map[string]any{"iso": map[string]any{"type": "string"}}}, "annotations": map[string]any{"readOnlyHint": yes}},
		{"name": "search", "description": "Search documents by query string", "inputSchema": map[string]any{"type": "object", "required": []string{"q"}, "properties": map[string]any{"q": map[string]any{"type": "string", "description": "The text to search for.", "minLength": 1}}}, "outputSchema": map[string]any{"type": "object", "required": []string{"hits"}, "properties": map[string]any{"hits": map[string]any{"type": "array"}}}, "annotations": map[string]any{"readOnlyHint": yes}},
		{"name": "delete_all", "description": "Deletes every document permanently", "inputSchema": map[string]any{"type": "object"}},
	}
	if f.personal {
		tools = append(tools, map[string]any{"name": "lookup_customer", "description": "Looks up a customer by e-mail address",
			"inputSchema":  map[string]any{"type": "object", "properties": map[string]any{"customer_email": map[string]any{"type": "string"}}},
			"outputSchema": map[string]any{"type": "object", "properties": map[string]any{"name": map[string]any{"type": "string", "description": "The customer's full name"}, "phone": map[string]any{"type": "string"}}},
			"annotations":  map[string]any{"readOnlyHint": yes}})
	}
	c.reply(map[string]any{"tools": tools})
}

func (f *fakeServer) callTool(c fakeRPC, req transport.Request) {
	var p struct {
		Name string         `json:"name"`
		Args map[string]any `json:"arguments"`
	}
	_ = json.Unmarshal(req.Params, &p)
	if p.Name == "" {
		c.fail(-32602, "missing name")
		return
	}
	f.mu.Lock()
	f.calls[p.Name]++
	f.mu.Unlock()
	switch p.Name {
	case "get_time":
		c.reply(map[string]any{"content": []map[string]any{{"type": "text", "text": "now"}}, "structuredContent": map[string]any{"iso": "2026-01-01T00:00:00Z"}})
	case "search":
		if _, ok := p.Args["q"]; !ok {
			c.reply(map[string]any{"isError": true, "content": []map[string]any{{"type": "text", "text": "q required"}}})
			return
		}
		c.reply(map[string]any{"content": []map[string]any{{"type": "text", "text": "ok"}, {"type": "image", "data": "AAAA", "mimeType": "image/png"}}, "structuredContent": map[string]any{"hits": "not-an-array"}})
	case "lookup_customer":
		c.reply(map[string]any{
			"content":           []map[string]any{{"type": "text", "text": "Found " + fakeCustomerName + ", " + fakeCustomerEmail + ", " + fakeCustomerPhone}},
			"structuredContent": map[string]any{"name": fakeCustomerName, "email": fakeCustomerEmail, "phone": fakeCustomerPhone},
		})
	case "delete_all":
		panic("destructive tool invoked")
	default:
		c.fail(-32602, "unknown tool")
	}
}

// serveRead answers resources/read and prompts/get, or refuses both when
// failReads is set, as a server does for a URI or prompt it lacks.
func (f *fakeServer) serveRead(c fakeRPC, req transport.Request) {
	switch {
	case f.failReads:
		c.fail(-32602, "no such "+req.Method)
	case req.Method == "resources/read":
		c.reply(map[string]any{"contents": []map[string]any{{"uri": "fake://doc/1", "mimeType": "text/plain", "text": "hello"}}})
	case !hasPromptArg(req, "doc"):
		// A correct server refuses a render missing a required argument.
		c.fail(-32602, "missing required argument: doc")
	default:
		c.reply(map[string]any{"messages": []map[string]any{{"role": "user", "content": map[string]any{"type": "text", "text": "Summarise"}}}})
	}
}

// hasPromptArg reports whether a prompts/get request carries the argument.
func hasPromptArg(req transport.Request, name string) bool {
	var p struct {
		Args map[string]string `json:"arguments"`
	}
	_ = json.Unmarshal(req.Params, &p)
	_, ok := p.Args[name]
	return ok
}
