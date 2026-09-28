// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"satellion.com/passmcp/transport"
)

// quirks are misbehaviours the fake can switch on, one per branch the
// phases look for.
type quirks struct {
	firstContactStatus int // status for an unauthenticated request (default 401)
	// open serves every request without credentials, which is what 40.55%
	// of live remote MCP servers measurably do. firstContactStatus cannot
	// model it: that one answers 200 with a body that is not a result, for
	// testing the "200 but not an initialize result" branch.
	open bool
	// readOnlyOnly drops the unannotated tool, leaving a catalogue that is
	// public and harmless.
	readOnlyOnly     bool
	challenge        string // WWW-Authenticate value; "-" means none
	garbageStatus    int    // status for a passmcp-invalid-* token (default 401)
	garbageNoHeader  bool
	prmEmptyServers  bool
	prmResource      string
	prmMissing       bool
	asMissing        bool
	asPKCE           []string // nil = S256
	asNoPKCE         bool
	asCIMD           bool
	asNoRegistration bool
	asHTTPIssuer     bool
	// prmAS replaces the authorization server the resource metadata names.
	prmAS string
	// prmExtra and asExtra add fields to the resource and authorization
	// server metadata; dpopNonce sets a DPoP-Nonce header on the 401.
	prmExtra          map[string]any
	asExtra           map[string]any
	dpopNonce         string
	tokenScope        string // scope returned in the token (default: requested)
	tokenNoExpiry     bool
	tokenShortExpiry  bool
	tokenType         string
	protocolVersion   string
	serverName        string
	serverVersion     string
	noCapabilities    bool
	noInstructions    bool
	stateless         bool
	unknownMethodCode int  // JSON-RPC code for unknown methods (default -32601)
	unknownMethodOK   bool // answer unknown methods with a result
	unknownMethodHTTP int  // answer unknown methods with this HTTP status
	wrongID           bool
	malformedOK       bool
	invalidParamsOK   bool
	unknownToolOK     bool
	lenientAccept     bool
	getStream         bool
	holdStream        bool // with getStream: keep the stream open and idle until the client leaves
	bogusSessionOK    bool
	lenientVersion    bool
	catalog           string // "", "dupes", "bad", "empty", "nocap", "relative"
	resourcesFail     bool
	readFail          bool
	resourcesEmpty    bool
	templatesFail     bool
	promptsFail       bool
	promptsEmpty      bool
	toolsFail         bool
	allToolsError     bool
	pingFail          bool
	noRetryAfter      bool
	burstFail         bool // fail every tools/call after burstFailAfter calls
	burstFailAfter    int
	rejectCredentials bool // 401 for every valid token (credentials rejected at initialize)
	// inputRequired makes every tools/call answer input_required, which is
	// a 2026-07-28 server behaving correctly rather than failing. The
	// variants below are the shapes that cannot be answered.
	inputRequired bool
	// mrtrEmpty says input is required and names no request, so there is no
	// retry a client can construct.
	mrtrEmpty bool
	// mrtrNoID omits the correlation id, so a client cannot say which
	// answer belongs to which request.
	mrtrNoID bool
	// mrtrStateOnly asks for a retry carrying requestState and names no
	// request, which the specification allows.
	mrtrStateOnly bool
	// mrtrUnknownMethod asks for a method a server may not send mid-call.
	mrtrUnknownMethod bool
	// pingNeedsInput answers the liveness call with input_required, which is
	// a different kind of wrong from a tool doing it: the whole purpose of a
	// liveness call is to be answerable with nobody present.
	pingNeedsInput bool
	// originOpen serves requests from any Origin, which the Streamable
	// HTTP transport forbids. By default the fake refuses a foreign one
	// with 403, as a correct server does; originStatus picks another
	// refusal status.
	originOpen   bool
	originStatus int
	// extraTools are appended to the catalogue, for the checks that read
	// what a set of tools can do together.
	extraTools []map[string]any
	// toolOutput replaces get_time's text result, for the output scan.
	toolOutput string
	// wrongAudience is a token the fake's authorization server issued for a
	// different resource. wrongAudienceAccepted makes the server take it,
	// which is the defect; otherwise it is refused with wrongAudienceStatus
	// (default 401).
	wrongAudience         string
	wrongAudienceAccepted bool
	wrongAudienceStatus   int
}

// fakeServer is a protected MCP server with its own authorization server,
// realistic enough to exercise every phase.
type fakeServer struct {
	srv       *httptest.Server
	mu        sync.Mutex
	hosts     map[string]int // requests received, by Host header
	sessions  map[string]bool
	seq       atomic.Int32
	tokens    map[string]bool // valid access tokens
	tokenReqs []map[string]string
	calls     map[string]int
	// knobs
	acceptAnyToken bool
	noChallenge    bool
	slowTool       time.Duration
	rateLimitAfter int
	burst          atomic.Int32
	q              quirks
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	f := &fakeServer{sessions: map[string]bool{}, tokens: map[string]bool{}, calls: map[string]int{}}
	mux := http.NewServeMux()
	f.hosts = map[string]int{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hosts[r.Host]++
		f.mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)
	base := f.srv.URL
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		if f.q.prmMissing {
			http.NotFound(w, r)
			return
		}
		servers := []string{base + "/as"}
		if f.q.asHTTPIssuer {
			servers = []string{"http://as.example.invalid/as"}
		}
		if f.q.prmAS != "" {
			servers = []string{f.q.prmAS}
		}
		if f.q.prmEmptyServers {
			servers = nil
		}
		res := base + "/mcp"
		if f.q.prmResource != "" {
			res = f.q.prmResource
		}
		prm := map[string]any{"resource": res, "authorization_servers": servers, "scopes_supported": []string{"mcp:read"}}
		for k, v := range f.q.prmExtra {
			prm[k] = v
		}
		_ = json.NewEncoder(w).Encode(prm)
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server/as", func(w http.ResponseWriter, r *http.Request) {
		if f.q.asMissing {
			http.NotFound(w, r)
			return
		}
		md := map[string]any{"issuer": base + "/as", "authorization_endpoint": base + "/as/authorize", "token_endpoint": base + "/as/token",
			"grant_types_supported": []string{"client_credentials", "authorization_code"}}
		if !f.q.asNoRegistration {
			md["registration_endpoint"] = base + "/as/register"
		}
		switch {
		case f.q.asNoPKCE:
		case f.q.asPKCE != nil:
			md["code_challenge_methods_supported"] = f.q.asPKCE
		default:
			md["code_challenge_methods_supported"] = []string{"S256"}
		}
		if f.q.asCIMD {
			md["client_id_metadata_document_supported"] = true
		}
		for k, v := range f.q.asExtra {
			md[k] = v
		}
		_ = json.NewEncoder(w).Encode(md)
	})
	mux.HandleFunc("/as/register", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "dyn", "client_secret": "dyn-secret-value"})
	})
	mux.HandleFunc("/as/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form := map[string]string{}
		for k := range r.PostForm {
			form[k] = r.PostForm.Get(k)
		}
		u, p, _ := r.BasicAuth()
		form["_basic_user"], form["_basic_pass"] = u, p
		f.mu.Lock()
		f.tokenReqs = append(f.tokenReqs, form)
		f.mu.Unlock()
		if u != "dyn" && u != "static-id" && r.PostForm.Get("grant_type") != "refresh_token" {
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
			return
		}
		if r.PostForm.Get("refresh_token") == "dead" {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		tok := fmt.Sprintf("issued-token-%d", f.seq.Add(1))
		f.mu.Lock()
		f.tokens[tok] = true
		f.mu.Unlock()
		resp := map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": 3600, "scope": r.PostForm.Get("scope")}
		if f.q.tokenScope != "" {
			resp["scope"] = f.q.tokenScope
		}
		if f.q.tokenNoExpiry {
			delete(resp, "expires_in")
		}
		if f.q.tokenShortExpiry {
			resp["expires_in"] = 5
		}
		if f.q.tokenType != "" {
			resp["token_type"] = f.q.tokenType
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/mcp", f.handle)
	return f
}

func (f *fakeServer) validToken(r *http.Request) bool {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" || f.q.rejectCredentials {
		return false
	}
	if f.q.wrongAudience != "" && tok == f.q.wrongAudience {
		return f.q.wrongAudienceAccepted
	}
	if f.acceptAnyToken {
		return true
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokens[tok]
}

func (f *fakeServer) unauthorized(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	garbage := strings.HasPrefix(tok, "passmcp-invalid-")
	status := 401
	if garbage && f.q.garbageStatus != 0 {
		status = f.q.garbageStatus
	}
	if !garbage && tok == "" && f.q.firstContactStatus != 0 {
		status = f.q.firstContactStatus
	}
	if tok != "" && tok == f.q.wrongAudience && f.q.wrongAudienceStatus != 0 {
		status = f.q.wrongAudienceStatus
	}
	hdr := fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource/mcp", scope="mcp:read"`, f.srv.URL)
	if f.q.challenge != "" {
		hdr = f.q.challenge
	}
	if f.noChallenge || hdr == "-" || (garbage && f.q.garbageNoHeader) {
		hdr = ""
	}
	if hdr != "" && status == 401 {
		w.Header().Set("WWW-Authenticate", hdr)
		if f.q.dpopNonce != "" {
			w.Header().Set("DPoP-Nonce", f.q.dpopNonce)
		}
	}
	if status/100 == 2 && garbage {
		// Pretend the garbage token was fine: fall through to the handler.
		return
	}
	w.WriteHeader(status)
	if status/100 == 2 {
		_, _ = w.Write([]byte("not a result"))
	}
}

func (f *fakeServer) handle(w http.ResponseWriter, r *http.Request) {
	// An open server serves everything to everyone. The gate has to be here
	// rather than inside unauthorized(): that one only chooses what to
	// write, and this one decides whether to answer at all.
	if !f.q.open && !f.validToken(r) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !strings.HasPrefix(tok, "passmcp-invalid-") || f.q.garbageStatus/100 != 2 {
			f.unauthorized(w, r)
			return
		}
	}
	if o := r.Header.Get("Origin"); o != "" && !f.q.originOpen && o != f.srv.URL {
		st := f.q.originStatus
		if st == 0 {
			st = http.StatusForbidden
		}
		w.WriteHeader(st)
		return
	}
	if r.Method == http.MethodGet {
		if f.q.getStream {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte(": hello\n\n"))
			if f.q.holdStream {
				if fl, ok := w.(http.Flusher); ok {
					fl.Flush()
				}
				<-r.Context().Done()
			}
			return
		}
		w.WriteHeader(405)
		return
	}
	if r.Header.Get("Accept") == "" && !f.q.lenientAccept {
		w.WriteHeader(406)
		return
	}
	if v := r.Header.Get(transport.HeaderProtocolVersion); v != "" && v != "2025-11-25" && v != f.q.protocolVersion && !f.q.lenientVersion {
		w.WriteHeader(400)
		return
	}
	var req transport.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if f.q.malformedOK {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(400)
		return
	}
	if sid := r.Header.Get(transport.HeaderSessionID); sid != "" && !f.q.bogusSessionOK {
		f.mu.Lock()
		ok := f.sessions[sid]
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(404)
			return
		}
	} else if sid == "" && req.Method != "initialize" && !f.q.stateless {
		w.WriteHeader(400)
		return
	}
	replyID := func() int64 {
		if req.ID == nil {
			return 0
		}
		if f.q.wrongID {
			return *req.ID + 1000
		}
		return *req.ID
	}
	reply := func(v any) {
		b, _ := json.Marshal(v)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":%s}`, replyID(), b)
	}
	rpcErr := func(code int, msg string) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"error":{"code":%d,"message":%q}}`, replyID(), code, msg)
	}
	yes, no := true, false
	switch req.Method {
	case "initialize":
		if !f.q.stateless {
			sid := fmt.Sprintf("sess-%d", f.seq.Add(1))
			f.mu.Lock()
			f.sessions[sid] = true
			f.mu.Unlock()
			w.Header().Set(transport.HeaderSessionID, sid)
		}
		pv := "2025-11-25"
		if f.q.protocolVersion != "" {
			pv = f.q.protocolVersion
		}
		res := map[string]any{"protocolVersion": pv, "capabilities": map[string]any{"tools": map[string]any{}, "resources": map[string]any{}, "prompts": map[string]any{}},
			"serverInfo": map[string]any{"name": "fake", "version": "1.0"}, "instructions": "Use wisely."}
		if f.q.noCapabilities {
			res["capabilities"] = map[string]any{}
		}
		if f.q.noInstructions {
			delete(res, "instructions")
		}
		if f.q.serverName != "" || f.q.serverVersion != "" {
			res["serverInfo"] = map[string]any{"name": f.q.serverName, "version": f.q.serverVersion}
		}
		reply(res)
	case "notifications/initialized":
		w.WriteHeader(202)
	case "ping":
		if f.q.pingFail {
			rpcErr(-32000, "ping broken")
			return
		}
		if f.q.pingNeedsInput {
			// A liveness call with a conversation attached to it, which is
			// the one request that cannot have one.
			reply(map[string]any{"resultType": "input_required", "inputRequests": map[string]any{
				"q1": map[string]any{"method": "elicitation/create", "params": map[string]any{"message": "are you there?"}},
			}})
			return
		}
		reply(map[string]any{})
	case "tools/list":
		if f.q.toolsFail {
			rpcErr(-32603, "tools broken")
			return
		}
		tools := []map[string]any{
			{"name": "get_time", "description": "Returns the current time in ISO 8601 format", "inputSchema": map[string]any{"type": "object"}, "outputSchema": map[string]any{"type": "object", "required": []string{"iso"}, "properties": map[string]any{"iso": map[string]any{"type": "string"}}}, "annotations": map[string]any{"readOnlyHint": yes}},
			{"name": "search", "description": "Search documents by query string", "inputSchema": map[string]any{"type": "object", "required": []string{"q"}, "properties": map[string]any{"q": map[string]any{"type": "string"}}}, "outputSchema": map[string]any{"type": "object", "required": []string{"hits"}, "properties": map[string]any{"hits": map[string]any{"type": "array"}}}, "annotations": map[string]any{"readOnlyHint": yes}},
			{"name": "lax", "description": "Accepts anything without validation", "inputSchema": map[string]any{"type": "object", "required": []string{"x"}, "properties": map[string]any{"x": map[string]any{"type": "string"}}}, "annotations": map[string]any{"readOnlyHint": yes}},
		}
		if !f.q.readOnlyOnly {
			tools = append(tools, map[string]any{"name": "delete_all", "description": "Deletes every document permanently", "inputSchema": map[string]any{"type": "object"}})
		}
		tools = append(tools, f.q.extraTools...)
		switch f.q.catalog {
		case "dupes":
			tools = append(tools, map[string]any{"name": "get_time", "description": "Duplicate name for the same thing", "inputSchema": map[string]any{"type": "object"}, "annotations": map[string]any{"readOnlyHint": yes}})
		case "bad":
			tools = []map[string]any{
				{"name": "nodesc", "inputSchema": map[string]any{"type": "string"}, "annotations": map[string]any{"readOnlyHint": yes}},
				{"name": "shortdesc", "description": "tiny", "inputSchema": map[string]any{"properties": map[string]any{}}, "outputSchema": map[string]any{"type": "object"}, "annotations": map[string]any{"readOnlyHint": yes}, "title": "T"},
				{"name": "brokenschema", "description": "Has an unparsable input schema", "inputSchema": "not-json-object", "annotations": map[string]any{"readOnlyHint": no, "destructiveHint": no}},
			}
		case "empty":
			tools = nil
		}
		reply(map[string]any{"tools": tools})
	case "tools/call":
		var p struct {
			Name string         `json:"name"`
			Args map[string]any `json:"arguments"`
		}
		_ = json.Unmarshal(req.Params, &p)
		if p.Name == "" {
			if f.q.invalidParamsOK {
				reply(map[string]any{"content": []map[string]any{}})
				return
			}
			rpcErr(-32602, "missing name")
			return
		}
		f.mu.Lock()
		f.calls[p.Name]++
		n := f.calls[p.Name]
		f.mu.Unlock()
		if f.rateLimitAfter > 0 && int(f.burst.Add(1)) > f.rateLimitAfter {
			if !f.q.noRetryAfter {
				w.Header().Set("Retry-After", "1")
			}
			w.WriteHeader(429)
			return
		}
		if f.q.burstFail && n > f.q.burstFailAfter {
			w.WriteHeader(500)
			return
		}
		if f.q.allToolsError {
			reply(map[string]any{"isError": true, "content": []map[string]any{{"type": "text", "text": "always fails"}}})
			return
		}
		switch {
		case f.q.mrtrEmpty:
			reply(map[string]any{"resultType": "input_required", "inputRequests": map[string]any{}})
			return
		case f.q.mrtrNoID:
			// The array form no revision defines, with the id missing too.
			reply(map[string]any{"resultType": "input_required", "inputRequests": []map[string]any{
				{"method": "elicitation/create", "params": map[string]any{"message": "which account?"}},
			}})
			return
		case f.q.mrtrStateOnly:
			reply(map[string]any{"resultType": "input_required", "requestState": "opaque-state"})
			return
		case f.q.mrtrUnknownMethod:
			reply(map[string]any{"resultType": "input_required", "inputRequests": map[string]any{
				"q1": map[string]any{"method": "tools/call", "params": map[string]any{"name": "x"}},
			}})
			return
		case f.q.inputRequired:
			reply(map[string]any{"resultType": "input_required", "inputRequests": map[string]any{
				"q1": map[string]any{"method": "elicitation/create", "params": map[string]any{"message": "which account?"}},
			}})
			return
		}
		switch p.Name {
		case "get_time":
			if f.slowTool > 0 {
				time.Sleep(f.slowTool)
			}
			text := "now"
			if f.q.toolOutput != "" {
				text = f.q.toolOutput
			}
			reply(map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "structuredContent": map[string]any{"iso": "2026-01-01T00:00:00Z"}})
		case "search":
			if _, ok := p.Args["q"]; !ok {
				reply(map[string]any{"isError": true, "content": []map[string]any{{"type": "text", "text": "q required"}}})
				return
			}
			reply(map[string]any{"content": []map[string]any{{"type": "text", "text": "ok"}}, "structuredContent": map[string]any{"hits": "not-an-array"}})
		case "lax", "shortdesc", "nodesc":
			reply(map[string]any{"content": []map[string]any{{"type": "text", "text": "whatever"}}})
		case "delete_all":
			panic("destructive tool invoked")
		default:
			if f.q.unknownToolOK {
				reply(map[string]any{"content": []map[string]any{{"type": "text", "text": "sure"}}})
				return
			}
			rpcErr(-32602, "unknown tool")
		}
	case "resources/list":
		if f.q.resourcesFail || f.q.catalog == "nocap" {
			rpcErr(-32601, "no resources")
			return
		}
		uri := "fake://doc/1"
		if f.q.catalog == "relative" {
			uri = "doc/1"
		}
		res := map[string]any{"uri": uri, "name": "doc1", "mimeType": "text/plain"}
		if f.q.catalog == "relative" {
			delete(res, "mimeType")
		}
		reply(map[string]any{"resources": []map[string]any{res}})
	case "resources/templates/list":
		if f.q.templatesFail {
			rpcErr(-32601, "no templates")
			return
		}
		reply(map[string]any{"resourceTemplates": []map[string]any{}})
	case "resources/read":
		if f.q.readFail {
			rpcErr(-32002, "read failed")
			return
		}
		if f.q.resourcesEmpty {
			reply(map[string]any{"contents": []map[string]any{}})
			return
		}
		reply(map[string]any{"contents": []map[string]any{{"uri": "fake://doc/1", "mimeType": "text/plain", "text": "hello"}}})
	case "prompts/list":
		if f.q.catalog == "nocap" {
			rpcErr(-32601, "no prompts")
			return
		}
		desc := "Summarise a doc"
		argDesc := "the doc"
		if f.q.catalog == "relative" {
			desc, argDesc = "", ""
		}
		reply(map[string]any{"prompts": []map[string]any{{"name": "summarise", "description": desc, "arguments": []map[string]any{{"name": "doc", "description": argDesc, "required": true}}}}})
	case "prompts/get":
		if f.q.promptsFail {
			rpcErr(-32602, "bad prompt")
			return
		}
		if f.q.promptsEmpty {
			reply(map[string]any{"messages": []map[string]any{}})
			return
		}
		reply(map[string]any{"messages": []map[string]any{{"role": "user", "content": map[string]any{"type": "text", "text": "Summarise"}}}})
	default:
		switch {
		case f.q.unknownMethodOK:
			reply(map[string]any{})
		case f.q.unknownMethodHTTP != 0:
			w.WriteHeader(f.q.unknownMethodHTTP)
		case f.q.unknownMethodCode != 0:
			rpcErr(f.q.unknownMethodCode, "nope")
		default:
			rpcErr(-32601, "method not found")
		}
	}
}
