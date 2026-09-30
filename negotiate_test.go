// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package passmcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"satellion.com/passmcp/transport"
)

// statelessServer is a 2026-07-28 server: it validates the required _meta
// and routing headers the way the specification says a server must, so a
// client that gets them wrong fails this test rather than passing quietly.
func statelessServer(t *testing.T, opts statelessOpts) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
				Meta      map[string]any `json:"_meta"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		id := req.ID
		if len(id) == 0 {
			id = json.RawMessage("null")
		}
		w.Header().Set("Content-Type", "application/json")

		rpcErr := func(status, code int, msg string, data string) {
			w.WriteHeader(status)
			if data == "" {
				data = "null"
			}
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":%q,"data":%s}}`, id, code, msg, data)
		}

		// Required per-request metadata.
		ver, _ := req.Params.Meta["io.modelcontextprotocol/protocolVersion"].(string)
		if ver == "" {
			rpcErr(http.StatusBadRequest, -32602, "missing protocolVersion in _meta", "")
			return
		}
		if _, ok := req.Params.Meta["io.modelcontextprotocol/clientCapabilities"]; !ok {
			rpcErr(http.StatusBadRequest, -32602, "missing clientCapabilities in _meta", "")
			return
		}
		// The header must agree with the body.
		if h := r.Header.Get("MCP-Protocol-Version"); h != ver {
			rpcErr(http.StatusBadRequest, transport.CodeHeaderMismatch, "protocol version header does not match body", "")
			return
		}
		if h := r.Header.Get("Mcp-Method"); h != req.Method {
			rpcErr(http.StatusBadRequest, transport.CodeHeaderMismatch, "Mcp-Method does not match body", "")
			return
		}
		if req.Method == "tools/call" {
			name, ok := transport.DecodeHeaderValue(r.Header.Get("Mcp-Name"))
			if !ok || name != req.Params.Name {
				rpcErr(http.StatusBadRequest, transport.CodeHeaderMismatch, "Mcp-Name does not match body", "")
				return
			}
			if opts.paramHeaders {
				if msg := paramHeaderMismatch(r.Header, req.Params.Arguments); msg != "" {
					rpcErr(http.StatusBadRequest, transport.CodeHeaderMismatch, msg, "")
					return
				}
			}
		}
		if ver != opts.version {
			rpcErr(http.StatusBadRequest, transport.CodeUnsupportedProtocolVersion, "unsupported version",
				fmt.Sprintf(`{"supported":[%q]}`, opts.version))
			return
		}
		if req.Method == "server/discover" && opts.noDiscover {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"no such method"}}`, id)
			return
		}
		switch req.Method {
		case "server/discover":
			if opts.metaServerInfo {
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","capabilities":{"tools":{}},"supportedVersions":["2026-07-28"],"instructions":"hi","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"stateless-demo","version":"2.0"}}}}`, id)
				return
			}
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","serverInfo":{"name":"stateless-demo","version":"2.0"},"capabilities":{"tools":{}},"instructions":"hi"}}`, id)
		case "tools/list":
			if opts.paramHeaders {
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","tools":[{"name":"t","description":"d","inputSchema":%s}]}}`, id, annotatedSchema)
				return
			}
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","tools":[{"name":"t","description":"d","inputSchema":{"type":"object"}}]}}`, id)
		default:
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete"}}`, id)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

type statelessOpts struct {
	version    string
	noDiscover bool
	// metaServerInfo answers server/discover the way the 2026-07-28
	// reference SDKs do: identity in _meta, not at the top level.
	metaServerInfo bool
	// paramHeaders lists a tool whose inputSchema annotates arguments with
	// x-mcp-header and answers -32020 when tools/call does not mirror them.
	paramHeaders bool
}

// annotatedSchema has one top-level and one nested x-mcp-header argument,
// and a number the binding does not mirror because it is not an integer.
const annotatedSchema = `{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"},"ratio":{"type":"number","x-mcp-header":"Ratio"},"opts":{"type":"object","properties":{"dry":{"type":"boolean","x-mcp-header":"Dry"}}}}}`

// paramHeaderMismatch is the strict server's check: every annotated
// argument the call carries is mirrored, and nothing else is.
func paramHeaderMismatch(h http.Header, args map[string]any) string {
	want := map[string]string{"Region": fmt.Sprint(args["region"])}
	if o, ok := args["opts"].(map[string]any); ok {
		want["Dry"] = fmt.Sprint(o["dry"])
	}
	for name, v := range want {
		got, ok := transport.DecodeHeaderValue(h.Get("Mcp-Param-" + name))
		if !ok || got != v {
			return "Mcp-Param-" + name + " does not match the argument"
		}
	}
	if h.Get("Mcp-Param-Ratio") != "" {
		return "Mcp-Param-Ratio mirrors a non-integer number"
	}
	return ""
}

func newClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := New(Config{Endpoint: srv.URL + "/mcp", HTTPClient: srv.Client(), ClientInfo: Implementation{Name: "passmcp", Version: "test"}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNegotiateStateless(t *testing.T) {
	srv := statelessServer(t, statelessOpts{version: transport.V20260728})
	c := newClient(t, srv)
	n, err := c.Negotiate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n.Era != EraStateless || n.Version != transport.V20260728 {
		t.Fatalf("negotiation = %+v", n)
	}
	if n.Discovered == nil || n.Discovered.ServerInfo.Name != "stateless-demo" {
		t.Errorf("server/discover result = %+v", n.Discovered)
	}
	if c.Negotiation() != n {
		t.Error("the negotiation must be recorded on the client")
	}
	if c.Transport().Dialect().Stateful() {
		t.Error("the transport must be left on the stateless binding")
	}
	// And the connection actually works afterwards, headers and all.
	tools, err := c.ListTools(context.Background())
	if err != nil {
		t.Fatalf("ListTools after negotiation: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "t" {
		t.Errorf("tools = %+v", tools)
	}
}

// The 2026-07-28 revision carries serverInfo in the discover result's _meta
// under a reserved key, and that is where the reference SDKs put it. A
// server that does so has identified itself; reading only the top-level
// field would call it anonymous and disbelieve every capability it declared.
func TestNegotiateReadsServerInfoFromMeta(t *testing.T) {
	srv := statelessServer(t, statelessOpts{version: transport.V20260728, metaServerInfo: true})
	c := newClient(t, srv)
	n, err := c.Negotiate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n.Era != EraStateless || n.Discovered == nil {
		t.Fatalf("era = %v, discovered = %+v (%s)", n.Era, n.Discovered, n.Reason)
	}
	if got := n.Discovered.ServerInfo; got.Name != "stateless-demo" || got.Version != "2.0" {
		t.Errorf("serverInfo = %+v, want it lifted from _meta", got)
	}
	if n.Discovered.Capabilities.Tools == nil {
		t.Errorf("capabilities were not kept: %+v", n.Discovered.Capabilities)
	}
	if got := n.Discovered.SupportedVersions; len(got) != 1 || got[0] != transport.V20260728 {
		t.Errorf("supportedVersions = %v", got)
	}
}

func TestDiscoverResultUnmarshal(t *testing.T) {
	cases := []struct {
		name, in string
		want     Implementation
		wantErr  bool
	}{
		{"top level", `{"serverInfo":{"name":"a","version":"1"}}`, Implementation{Name: "a", Version: "1"}, false},
		{"meta", `{"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"b","version":"2"}}}`, Implementation{Name: "b", Version: "2"}, false},
		{"top level wins", `{"serverInfo":{"name":"a","version":"1"},"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"b","version":"2"}}}`, Implementation{Name: "a", Version: "1"}, false},
		{"neither", `{"capabilities":{}}`, Implementation{}, false},
		{"malformed meta", `{"_meta":{"io.modelcontextprotocol/serverInfo":"nope"}}`, Implementation{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var d DiscoverResult
			err := json.Unmarshal([]byte(tc.in), &d)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && d.ServerInfo != tc.want {
				t.Errorf("serverInfo = %+v, want %+v", d.ServerInfo, tc.want)
			}
		})
	}
}

// server/discover is optional. A server that does not implement it is still
// a stateless server, and must not be mistaken for a legacy one.
func TestNegotiateStatelessWithoutDiscover(t *testing.T) {
	srv := statelessServer(t, statelessOpts{version: transport.V20260728, noDiscover: true})
	c := newClient(t, srv)
	n, err := c.Negotiate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n.Era != EraStateless {
		t.Fatalf("era = %v (%s)", n.Era, n.Reason)
	}
	if n.Discovered != nil {
		t.Errorf("nothing was discovered: %+v", n.Discovered)
	}
	if !strings.Contains(n.Reason, "server/discover") {
		t.Errorf("the reason should say why: %q", n.Reason)
	}
}

// legacyServer speaks only the handshake revisions and answers a stateless
// request the way a server that predates them would: a bare 400 with no
// JSON-RPC error body.
func legacyServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		id := req.ID
		if len(id) == 0 {
			id = json.RawMessage("null")
		}
		if req.Method == "server/discover" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("Bad Request"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Mcp-Session-Id", "sess-legacy")
		switch req.Method {
		case "initialize":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"legacy","version":"1.0"}}}`, id)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[]}}`, id)
		default:
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{}}`, id)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestNegotiateFallsBackToHandshake(t *testing.T) {
	srv := legacyServer(t)
	c := newClient(t, srv)
	n, err := c.Negotiate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n.Era != EraSession {
		t.Fatalf("era = %v (%s)", n.Era, n.Reason)
	}
	if n.Version != transport.V20251125 {
		t.Errorf("version = %q", n.Version)
	}
	if !c.Transport().Dialect().Stateful() {
		t.Error("the transport must be left on the session binding")
	}
	if c.Transport().SessionID() != "sess-legacy" {
		t.Errorf("the session assigned during the handshake must survive: %q", c.Transport().SessionID())
	}
	if !strings.Contains(n.Reason, "2025-11-25") {
		t.Errorf("the reason should name the negotiated version: %q", n.Reason)
	}
}

// A server that answers with a modern error is a modern server. Falling
// back to a handshake would hide a real problem behind a version change.
func TestNegotiateDoesNotFallBackOnModernError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32021,"message":"needs elicitation","data":{"requiredCapabilities":["elicitation"]}}}`))
	}))
	defer srv.Close()

	c := newClient(t, srv)
	n, err := c.Negotiate(context.Background())
	if err == nil {
		t.Fatal("a modern rejection must be reported, not worked around")
	}
	var mc *transport.MissingCapabilityError
	if !errors.As(err, &mc) {
		t.Errorf("the cause should survive: %v", err)
	}
	if n == nil || n.Era != EraStateless {
		t.Errorf("the server is still stateless: %+v", n)
	}
}

// When the server names the versions it supports, take one we share rather
// than dropping to a handshake.
func TestNegotiateHonoursAdvertisedVersions(t *testing.T) {
	srv := statelessServer(t, statelessOpts{version: transport.V20260728})
	c := newClient(t, srv)
	// Pretend passmcp offers a newer version first that this server refuses.
	orig := StatelessVersions
	StatelessVersions = []string{"2099-01-01", transport.V20260728}
	t.Cleanup(func() { StatelessVersions = orig })

	n, err := c.Negotiate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n.Era != EraStateless || n.Version != transport.V20260728 {
		t.Fatalf("negotiation = %+v", n)
	}
	if len(n.ServerSupported) == 0 {
		t.Errorf("the versions the server named should be recorded: %+v", n)
	}
	if !strings.Contains(n.Reason, transport.V20260728) {
		t.Errorf("reason = %q", n.Reason)
	}
}

func TestNegotiateUnreachableServer(t *testing.T) {
	c, err := New(Config{Endpoint: "http://127.0.0.1:1/mcp", ClientInfo: Implementation{Name: "passmcp"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Negotiate(context.Background()); err == nil {
		t.Fatal("an unreachable server must be an error, not a fallback verdict")
	}
}

// A handshake-era server handed server/discover answers -32601 as an
// ordinary JSON-RPC error at HTTP 200, because it does not know the method
// either. Reading that as "a stateless server without the optional RPC"
// would label every legacy server as current — the one mistake this
// detection exists to avoid.
func TestNegotiateLegacyMethodNotFoundIsNotStateless(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		id := req.ID
		if len(id) == 0 {
			id = json.RawMessage("null")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Mcp-Session-Id", "sess-1")
		switch req.Method {
		case "initialize":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"legacy","version":"1"}}}`, id)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		default:
			// HTTP 200 with a JSON-RPC error: the handshake-era shape.
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"no such method"}}`, id)
		}
	}))
	defer srv.Close()

	c := newClient(t, srv)
	n, err := c.Negotiate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n.Era != EraStateless {
		// expected
	} else {
		t.Fatalf("a 200 + -32601 must not be read as a stateless server: %+v", n)
	}
	if n.Era != EraSession || n.Version != transport.V20251125 {
		t.Fatalf("negotiation = %+v", n)
	}
}

// The stateless shape is HTTP 404 with a -32601 body, which is how a
// current server reports an RPC it does not implement.
func TestNegotiateStatelessMethodNotFoundIsStateless(t *testing.T) {
	srv := statelessServer(t, statelessOpts{version: transport.V20260728, noDiscover: true})
	c := newClient(t, srv)
	n, err := c.Negotiate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n.Era != EraStateless {
		t.Fatalf("a 404 + -32601 is a stateless server without the optional RPC: %+v", n)
	}
}

// TestExtensionIDsReadsCapabilities. The 2026-07-28 schema puts extensions
// in capabilities.extensions, keyed by identifier; a top-level list is not
// where a client looks, and must not be reported as advertised.
func TestExtensionIDsReadsCapabilities(t *testing.T) {
	var d DiscoverResult
	body := `{"capabilities":{"extensions":{"io.modelcontextprotocol/tasks":{},"com.example.mcp/billing":{"tier":"gold"}}},"extensions":["top.level/ignored"]}`
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatal(err)
	}
	got := d.ExtensionIDs()
	if len(got) != 2 || got[0] != "com.example.mcp/billing" || got[1] != "io.modelcontextprotocol/tasks" {
		t.Errorf("ExtensionIDs = %v, want the two capability keys, sorted", got)
	}
	if string(d.ExtensionSettings["com.example.mcp/billing"]) != `{"tier":"gold"}` {
		t.Errorf("settings were not kept: %s", d.ExtensionSettings["com.example.mcp/billing"])
	}
	var bad DiscoverResult
	if err := json.Unmarshal([]byte(`{"serverInfo":{"name":"s","version":"1"},"capabilities":{"extensions":["not","an","object"]}}`), &bad); err != nil {
		t.Fatalf("one malformed field lost the whole result: %v", err)
	}
	if !bad.ExtensionsMalformed || bad.ExtensionIDs() != nil || bad.ServerInfo.Name != "s" {
		t.Errorf("malformed extensions: %+v", bad)
	}
	var nilResult *DiscoverResult
	if nilResult.ExtensionIDs() != nil {
		t.Error("a nil result advertised extensions")
	}
}

// TestStatelessMirrorsAnnotatedArguments: under 2026-07-28 a tools/call
// mirrors every x-mcp-header argument into Mcp-Param-{Name}; a strict server
// answers -32020 otherwise, and the failure would be passmcp's, not its.
func TestStatelessMirrorsAnnotatedArguments(t *testing.T) {
	srv := statelessServer(t, statelessOpts{version: transport.V20260728, paramHeaders: true})
	c := newClient(t, srv)
	if _, err := c.Negotiate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListTools(context.Background()); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"region": "eu-west", "ratio": 0.5, "opts": map[string]any{"dry": false}}
	if _, err := c.CallTool(context.Background(), "t", args); err != nil {
		t.Fatalf("tools/call with annotated arguments: %v", err)
	}
}
