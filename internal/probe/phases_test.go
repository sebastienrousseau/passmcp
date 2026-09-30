// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp/auth"
	"satellion.com/passmcp/diagnostics"
	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/telemetry"
)

func ccCreds() *creds.Credentials {
	return &creds.Credentials{Mode: creds.ModeClientCredentials, ClientID: "static-id", ClientSecret: "static-secret-value"}
}

func run(t *testing.T, f *fakeServer, cr *creds.Credentials, mut func(*Options)) (*Session, map[string]Finding) {
	t.Helper()
	o := Options{Endpoint: f.srv.URL + "/mcp", Creds: cr, Recorder: telemetry.New(), HTTPClient: f.srv.Client(), Version: "t", RPS: -1, Samples: 2, Concurrency: 2}
	if mut != nil {
		mut(&o)
	}
	s, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	return s, findingsByID(s)
}

func expect(t *testing.T, fs map[string]Finding, id string, st Status, contains string) {
	t.Helper()
	f, ok := fs[id]
	if !ok {
		t.Errorf("%s: missing", id)
		return
	}
	if f.Status != st || !strings.Contains(f.Detail, contains) {
		t.Errorf("%s: got %s %q, want %s containing %q", id, f.Status, f.Detail, st, contains)
	}
}

func TestRunValidation(t *testing.T) {
	if _, err := Run(context.Background(), Options{Endpoint: "/relative"}); err == nil {
		t.Error("relative endpoint must fail")
	}
	if _, err := Run(context.Background(), Options{Endpoint: "https://x/mcp", Creds: &creds.Credentials{Mode: creds.ModeAuthorizationCode}, Only: []string{"none-such"}}); err != nil {
		t.Errorf("no phases selected: %v", err)
	}
	if worst([]Finding{{Status: Info}}) != Pass || worst(nil) != Skip || worst([]Finding{{Status: Skip}, {Status: Warn}}) != Warn {
		t.Error("worst ordering")
	}
	if truncate("  abc  ", 2) != "ab…" || truncate("abc", 5) != "abc" {
		t.Error("truncate")
	}
	if !isLoopback("localhost") || isLoopback("example.com") {
		t.Error("isLoopback")
	}
	if dcrNote(&auth.ServerMetadata{}) != "" || dcrNote(&auth.ServerMetadata{RegistrationEndpoint: "x"}) == "" {
		t.Error("dcrNote")
	}
}

func TestNetPhaseFailures(t *testing.T) {
	rec := telemetry.New()
	s, err := Run(context.Background(), Options{Endpoint: "https://nonexistent.invalid/mcp", Recorder: rec, Only: []string{"net", "handshake"}})
	if err != nil {
		t.Fatal(err)
	}
	fs := findingsByID(s)
	expect(t, fs, "net.scheme", Pass, "https")
	expect(t, fs, "net.dns", Fail, "lookup failed")
	if s.Results[1].Status != Skip || !strings.Contains(s.Results[1].Skipped, "does not resolve") {
		t.Errorf("later phase not skipped: %+v", s.Results[1])
	}
	s, _ = Run(context.Background(), Options{Endpoint: "http://127.0.0.1:1/mcp", Recorder: telemetry.New(), Only: []string{"net"}})
	fs = findingsByID(s)
	expect(t, fs, "net.scheme", Info, "loopback")
	expect(t, fs, "net.tcp", Fail, "connect failed")
	// Plain http to a public host is critical (no connection is attempted after DNS on a bogus host).
	s, _ = Run(context.Background(), Options{Endpoint: "http://nonexistent.invalid/mcp", Recorder: telemetry.New(), Only: []string{"net"}})
	expect(t, findingsByID(s), "net.scheme", Fail, "clear text")
	// A TLS server whose certificate the system does not trust fails the handshake honestly.
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer tls.Close()
	s, _ = Run(context.Background(), Options{Endpoint: tls.URL + "/mcp", Recorder: telemetry.New(), Only: []string{"net", "discovery"}})
	fs = findingsByID(s)
	expect(t, fs, "net.tcp", Pass, "connected")
	expect(t, fs, "net.tls", Fail, "handshake failed")
	if s.blocked == "" {
		t.Error("TLS failure must block")
	}
}

func TestDiscoveryBranches(t *testing.T) {
	// 403 on first contact, then no Bearer scheme in the challenge.
	f := newFakeServer(t)
	f.q.firstContactStatus = 403
	_, fs := run(t, f, ccCreds(), nil)
	expect(t, fs, "discovery.first_contact", Warn, "403")
	expect(t, fs, "discovery.challenge", Warn, "no WWW-Authenticate")
	expect(t, fs, "discovery.prm", Pass, "found")
	expect(t, fs, "handshake.initialize", Pass, "")

	f = newFakeServer(t)
	f.q.firstContactStatus = 500
	s, fs := run(t, f, ccCreds(), nil)
	expect(t, fs, "discovery.first_contact", Fail, "unexpected HTTP 500")
	if s.blocked == "" {
		t.Error("must block")
	}

	f = newFakeServer(t)
	f.q.challenge = `Basic realm="x"`
	_, fs = run(t, f, ccCreds(), nil)
	expect(t, fs, "discovery.challenge", Warn, "no Bearer scheme")

	f = newFakeServer(t)
	f.q.challenge = `Bearer realm="x"`
	_, fs = run(t, f, ccCreds(), nil)
	expect(t, fs, "discovery.challenge", Warn, "lacks resource_metadata")
	expect(t, fs, "discovery.prm", Pass, "found")

	f = newFakeServer(t)
	f.q.prmEmptyServers = true
	s, fs = run(t, f, ccCreds(), nil)
	expect(t, fs, "discovery.prm", Fail, "no authorization_servers")
	if s.blocked == "" {
		t.Error("must block")
	}

	f = newFakeServer(t)
	f.q.prmMissing = true
	f.noChallenge = true
	_, fs = run(t, f, ccCreds(), nil)
	expect(t, fs, "discovery.prm", Fail, "not found")

	f = newFakeServer(t)
	f.q.prmResource = "https://other.example/mcp"
	f.q.asMissing = true
	s, fs = run(t, f, ccCreds(), nil)
	// A resource that names another endpoint is now refused, not tolerated:
	// that binding is what stops a token mix-up.
	expect(t, fs, "discovery.prm.resource", Fail, "differs")
	expect(t, fs, "discovery.as", Fail, "no authorization server published metadata")
	if s.blocked == "" {
		t.Error("must block")
	}

	f = newFakeServer(t)
	f.q.prmResource = " "
	f.q.asNoPKCE = true
	f.q.asNoRegistration = true
	_, fs = run(t, f, &creds.Credentials{Mode: creds.ModeClientCredentials, ClientID: "static-id", ClientSecret: "s"}, nil)
	expect(t, fs, "discovery.as.pkce", Warn, "absent")
	expect(t, fs, "discovery.registration", Warn, "neither")

	f = newFakeServer(t)
	f.q.asPKCE = []string{"plain"}
	f.q.asCIMD = true
	_, fs = run(t, f, &creds.Credentials{Mode: creds.ModeClientCredentials, ClientMetadataURL: "https://c/md"}, nil)
	expect(t, fs, "discovery.as.pkce", Fail, "S256 not supported")
	expect(t, fs, "discovery.registration", Pass, "metadata documents")
	expect(t, fs, "auth.registration", Pass, "cimd")

	// --token-url override bypasses discovery.
	f = newFakeServer(t)
	cr := ccCreds()
	cr.TokenURL = f.srv.URL + "/as/token"
	_, fs = run(t, f, cr, nil)
	expect(t, fs, "discovery.override", Info, "token endpoint")
	expect(t, fs, "auth.token", Pass, "token issued")
	cr = ccCreds()
	cr.TokenURL = "http://127.0.0.1:1/token"
	s, fs = run(t, f, cr, nil)
	expect(t, fs, "auth.token", Fail, "")
	if s.blocked == "" {
		t.Error("must block on token failure")
	}

	// Bearer mode: informational discovery, both outcomes.
	f = newFakeServer(t)
	f.acceptAnyToken = true
	_, fs = run(t, f, &creds.Credentials{Mode: creds.ModeBearer, Token: "operator-token"}, func(o *Options) { o.Only = []string{"net", "discovery", "auth"} })
	expect(t, fs, "discovery.prm", Pass, "authorization server")
	f = newFakeServer(t)
	f.acceptAnyToken = true
	f.q.prmMissing = true
	f.noChallenge = true
	_, fs = run(t, f, &creds.Credentials{Mode: creds.ModeBearer, Token: "operator-token"}, func(o *Options) { o.Only = []string{"net", "discovery", "auth"} })
	expect(t, fs, "discovery.prm", Warn, "not discoverable")
	expect(t, fs, "auth.rejects_garbage", Fail, "made-up")
}

// TestAuthorizationServerNamingAnotherIssuerBlocks is RFC 8414 §3.3: the
// metadata fetched for an issuer must name that issuer, or it is not used.
// Before the check, a document claiming to be another authorization server
// was accepted and its token endpoint was sent the client secret.
func TestAuthorizationServerNamingAnotherIssuerBlocks(t *testing.T) {
	f := newFakeServer(t)
	f.q.asIssuer = "https://idp.example/as"
	s, fs := run(t, f, ccCreds(), nil)
	expect(t, fs, "discovery.as", Fail, "issuer")
	if fs["discovery.as"].Severity != Critical || s.blocked == "" {
		t.Errorf("an issuer mismatch must be critical and block: %+v, blocked %q", fs["discovery.as"], s.blocked)
	}
	if _, ok := fs["auth.token"]; ok && fs["auth.token"].Status == Pass {
		t.Error("a token was obtained through metadata that named another issuer")
	}
}

func TestAuthBranches(t *testing.T) {
	// Garbage token answered with 403, then 401 without header.
	f := newFakeServer(t)
	f.q.garbageStatus = 403
	_, fs := run(t, f, ccCreds(), func(o *Options) { o.Only = []string{"net", "discovery", "auth"} })
	expect(t, fs, "auth.rejects_garbage", Warn, "403")
	f = newFakeServer(t)
	f.q.garbageNoHeader = true
	_, fs = run(t, f, ccCreds(), func(o *Options) { o.Only = []string{"net", "discovery", "auth"} })
	expect(t, fs, "auth.rejects_garbage", Warn, "without WWW-Authenticate")
	f = newFakeServer(t)
	f.q.garbageStatus = 500
	_, fs = run(t, f, ccCreds(), func(o *Options) { o.Only = []string{"net", "discovery", "auth"} })
	expect(t, fs, "auth.rejects_garbage", Warn, "HTTP 500")

	// Token shape findings.
	f = newFakeServer(t)
	f.q.tokenNoExpiry = true
	f.q.tokenType = "mac"
	f.q.tokenScope = "mcp:other"
	_, fs = run(t, f, ccCreds(), func(o *Options) { o.Only = []string{"net", "discovery", "auth"} })
	expect(t, fs, "auth.token.type", Warn, "mac")
	expect(t, fs, "auth.token.expiry", Warn, "unknown")
	expect(t, fs, "auth.token.scope", Warn, "granted")
	f = newFakeServer(t)
	f.q.tokenShortExpiry = true
	f.q.tokenScope = " "
	_, fs = run(t, f, ccCreds(), func(o *Options) { o.Only = []string{"net", "discovery", "auth"} })
	expect(t, fs, "auth.token.expiry", Warn, "expires in")

	// Open server with credentials supplied.
	f = newFakeServer(t)
	f.acceptAnyToken = true
	f.noChallenge = true
	orig := f.srv.Config.Handler
	f.srv.Config.Handler = httpHandlerFunc(func(w httpResponseWriter, r httpRequest) {
		if r.Header.Get("Authorization") == "" {
			r.Header.Set("Authorization", "Bearer anything")
		}
		orig.ServeHTTP(w, r)
	})
	_, fs = run(t, f, &creds.Credentials{Mode: creds.ModeBearer, Token: "tok-1234"}, func(o *Options) { o.Only = []string{"net", "discovery", "auth", "handshake"} })
	expect(t, fs, "discovery.creds_unused", Warn, "did not demand")
	expect(t, fs, "auth.mode", Info, "")
	if _, ok := fs["auth.rejects_garbage"]; ok {
		t.Error("garbage probe must not run against an open server")
	}

	// Authorization-code mode from the store: missing, refreshable, and dead.
	f = newFakeServer(t)
	store := &creds.Store{Path: filepath.Join(t.TempDir(), "tokens.json")}
	ac := &creds.Credentials{Mode: creds.ModeAuthorizationCode}
	s, fs := run(t, f, ac, func(o *Options) { o.Store = store; o.Only = []string{"net", "discovery", "auth", "handshake"} })
	expect(t, fs, "auth.token", Fail, "no stored token")
	if s.blocked == "" {
		t.Error("must block")
	}
	if err := store.Put(creds.StoredToken{Endpoint: f.srv.URL + "/mcp", AccessToken: "stale", RefreshToken: "rt-ok", TokenURL: f.srv.URL + "/as/token", ClientID: "static-id", ClientSecret: "s", Issuer: f.srv.URL + "/as", Expiry: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	_, fs = run(t, f, ac, func(o *Options) { o.Store = store })
	expect(t, fs, "auth.token", Pass, "loaded from store")
	expect(t, fs, "handshake.initialize", Pass, "")
	expect(t, fs, "resilience.token_refresh", Pass, "")
	if err := store.Put(creds.StoredToken{Endpoint: f.srv.URL + "/mcp", AccessToken: "stale", RefreshToken: "dead", TokenURL: f.srv.URL + "/as/token", ClientID: "static-id", Expiry: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	_, fs = run(t, f, ac, func(o *Options) { o.Store = store; o.Only = []string{"net", "discovery", "auth"} })
	expect(t, fs, "auth.token", Fail, "unusable")

	// Credentials rejected at initialize.
	f = newFakeServer(t)
	f.q.rejectCredentials = true
	s, fs = run(t, f, &creds.Credentials{Mode: creds.ModeBearer, Token: "tok-1234"}, nil)
	expect(t, fs, "handshake.initialize", Fail, "answered 401")
	if !strings.Contains(s.blocked, "rejected") {
		t.Errorf("blocked = %q", s.blocked)
	}
}

func TestHandshakeAndProtocolBranches(t *testing.T) {
	f := newFakeServer(t)
	f.acceptAnyToken = true
	f.q.protocolVersion = "1999-01-01"
	s, fs := run(t, f, &creds.Credentials{Mode: creds.ModeBearer, Token: "tok-1234"}, nil)
	expect(t, fs, "handshake.initialize", Fail, "unsupported protocol")
	if s.blocked == "" {
		t.Error("must block")
	}
	bearer := &creds.Credentials{Mode: creds.ModeBearer, Token: "tok-1234"}
	f = newFakeServer(t)
	f.acceptAnyToken = true
	f.q.protocolVersion = "2025-06-18"
	f.q.serverName = "x"
	f.q.noCapabilities = true
	f.q.noInstructions = true
	f.q.stateless = true
	_, fs = run(t, f, bearer, func(o *Options) { o.Only = []string{"net", "discovery", "auth", "handshake", "resilience"} })
	expect(t, fs, "handshake.protocol_version", Info, "2025-06-18")
	expect(t, fs, "handshake.server_info", Warn, "version is empty")
	expect(t, fs, "handshake.capabilities", Warn, "no capabilities")
	expect(t, fs, "handshake.instructions", Info, "none")
	expect(t, fs, "handshake.session", Info, "stateless")
	expect(t, fs, "resilience.session_reinit", Skip, "stateless")
	f = newFakeServer(t)
	f.acceptAnyToken = true
	f.q.serverVersion = "1"
	_, fs = run(t, f, bearer, func(o *Options) { o.Only = []string{"net", "discovery", "auth", "handshake"} })
	expect(t, fs, "handshake.server_info", Fail, "name is empty")

	// Lenient / wrong protocol behaviour.
	f = newFakeServer(t)
	f.acceptAnyToken = true
	f.q.unknownMethodCode = -1
	f.q.wrongID = true
	f.q.malformedOK = true
	f.q.invalidParamsOK = true
	f.q.unknownToolOK = true
	f.q.lenientAccept = true
	f.q.getStream = true
	f.q.bogusSessionOK = true
	f.q.lenientVersion = true
	_, fs = run(t, f, bearer, func(o *Options) { o.Only = []string{"net", "discovery", "auth", "handshake", "protocol", "resilience"} })
	expect(t, fs, "protocol.unknown_method", Warn, "-32601 expected")
	expect(t, fs, "protocol.id_echo", Fail, "sent id")
	// The detail is the evidence a reader acts on, so it names both ids by
	// value: the fake answers with the request's id plus 1000.
	var sent, got int64
	if _, err := fmt.Sscanf(fs["protocol.id_echo"].Detail, "sent id %d, got %d", &sent, &got); err != nil || got != sent+1000 {
		t.Errorf("protocol.id_echo detail %q does not name both ids", fs["protocol.id_echo"].Detail)
	}
	expect(t, fs, "protocol.malformed_json", Fail, "truncated body")
	expect(t, fs, "protocol.invalid_params", Fail, "succeeded")
	expect(t, fs, "protocol.unknown_tool", Fail, "returned success")
	expect(t, fs, "protocol.accept_header", Info, "lenient")
	expect(t, fs, "protocol.get_stream", Pass, "event-stream")
	expect(t, fs, "protocol.bogus_session", Warn, "never issued")
	expect(t, fs, "protocol.version_header", Info, "accepted")
	expect(t, fs, "resilience.session_reinit", Warn, "accepted the bogus session")

	f = newFakeServer(t)
	f.acceptAnyToken = true
	f.q.unknownMethodHTTP = 400
	f.q.pingFail = true
	_, fs = run(t, f, bearer, func(o *Options) { o.Only = []string{"net", "discovery", "auth", "handshake", "protocol", "resilience"} })
	expect(t, fs, "protocol.unknown_method", Warn, "HTTP 400")
	expect(t, fs, "protocol.ping", Fail, "")
	expect(t, fs, "resilience.session_reinit", Fail, "recovery failed")
	f = newFakeServer(t)
	f.acceptAnyToken = true
	f.q.unknownMethodOK = true
	_, fs = run(t, f, bearer, func(o *Options) { o.Only = []string{"net", "discovery", "auth", "handshake", "protocol"} })
	expect(t, fs, "protocol.unknown_method", Fail, "no error")
}

func TestCatalogBranches(t *testing.T) {
	bearer := &creds.Credentials{Mode: creds.ModeBearer, Token: "tok-1234"}
	f := newFakeServer(t)
	f.acceptAnyToken = true
	f.q.catalog = "dupes"
	_, fs := run(t, f, bearer, func(o *Options) { o.Only = []string{"net", "discovery", "auth", "handshake", "catalog"} })
	expect(t, fs, "catalog.tools.unique", Fail, "get_time")

	f = newFakeServer(t)
	f.acceptAnyToken = true
	f.q.catalog = "bad"
	f.q.catalog = "bad"
	_, fs = run(t, f, bearer, func(o *Options) { o.Only = []string{"net", "discovery", "auth", "handshake", "catalog", "execution"} })
	expect(t, fs, "catalog.tools.descriptions", Fail, "missing")
	expect(t, fs, "catalog.tools.input_schema", Fail, "nodesc")
	expect(t, fs, "catalog.tools.annotations", Pass, "")
	expect(t, fs, "catalog.tools.output_schema", Info, "without outputSchema")
	if _, ok := fs["catalog.tools.title"]; !ok {
		t.Error("title finding expected")
	}
	// brokenschema is mutating-but-not-destructive; with AllowMutations it is attempted and its schema is unparsable.
	found := false
	for _, r := range fsSession(t, f, bearer).ToolResults {
		if r.Name == "brokenschema" && strings.Contains(r.SkipReason, "unparsable") {
			found = true
		}
	}
	if !found {
		t.Error("unparsable inputSchema should be a skip reason")
	}

	f = newFakeServer(t)
	f.acceptAnyToken = true
	f.q.catalog = "empty"
	f.q.resourcesFail = true
	f.q.templatesFail = true
	_, fs = run(t, f, bearer, func(o *Options) {
		o.Only = []string{"net", "discovery", "auth", "handshake", "catalog", "execution", "performance"}
	})
	expect(t, fs, "catalog.tools.list", Pass, "0 tools")
	expect(t, fs, "catalog.resources.list", Fail, "listing failed")
	expect(t, fs, "execution.tools", Skip, "no tools")
	expect(t, fs, "performance.tools", Skip, "no tool completed")

	f = newFakeServer(t)
	f.acceptAnyToken = true
	f.q.catalog = "nocap"
	f.q.noCapabilities = true
	f.q.toolsFail = true
	_, fs = run(t, f, bearer, func(o *Options) { o.Only = []string{"net", "discovery", "auth", "handshake", "catalog"} })
	expect(t, fs, "catalog.tools.list", Info, "not supported")
	expect(t, fs, "catalog.resources.list", Info, "not supported")
	expect(t, fs, "catalog.prompts.list", Info, "not supported")
	expect(t, fs, "catalog.empty", Fail, "no tools")

	f = newFakeServer(t)
	f.acceptAnyToken = true
	f.q.noCapabilities = true
	_, fs = run(t, f, bearer, func(o *Options) { o.Only = []string{"net", "discovery", "auth", "handshake", "catalog"} })
	expect(t, fs, "catalog.tools.list", Warn, "not declared")
	expect(t, fs, "catalog.resources.list", Warn, "without the capability")
	expect(t, fs, "catalog.prompts.list", Warn, "without the capability")

	f = newFakeServer(t)
	f.acceptAnyToken = true
	f.q.catalog = "relative"
	f.q.templatesFail = true
	_, fs = run(t, f, bearer, func(o *Options) { o.Only = []string{"net", "discovery", "auth", "handshake", "catalog"} })
	expect(t, fs, "catalog.resources.uris", Fail, "doc/1")
	expect(t, fs, "catalog.resources.mime", Info, "without mimeType")
	expect(t, fs, "catalog.resources.templates", Info, "not supported")
	expect(t, fs, "catalog.prompts.descriptions", Warn, "undescribed")

	if !schemaIsObject([]byte(`{"type":["null","object"]}`)) || schemaIsObject([]byte(`{"type":["string"]}`)) || schemaIsObject([]byte(`{bad`)) || schemaIsObject([]byte(`{"type":5}`)) {
		t.Error("schemaIsObject")
	}
	if !strings.Contains(list([]string{"a", "b", "c", "d", "e", "f", "g", "h", "i"}), "+1 more") {
		t.Error("list truncation")
	}
}

func fsSession(t *testing.T, f *fakeServer, cr *creds.Credentials) *Session {
	t.Helper()
	s, _ := run(t, f, cr, func(o *Options) {
		o.Only = []string{"net", "discovery", "auth", "handshake", "catalog", "execution"}
		o.Policy = diagnostics.Policy{AllowMutations: true}
	})
	return s
}

func TestExecutionBranches(t *testing.T) {
	bearer := &creds.Credentials{Mode: creds.ModeBearer, Token: "tok-1234"}
	f := newFakeServer(t)
	f.acceptAnyToken = true
	f.q.allToolsError = true
	f.q.resourcesEmpty = true
	f.q.promptsEmpty = true
	_, fs := run(t, f, bearer, func(o *Options) { o.Only = []string{"net", "discovery", "auth", "handshake", "catalog", "execution"} })
	expect(t, fs, "execution.tools", Warn, "every call returned isError")
	expect(t, fs, "execution.resources", Warn, "empty")
	expect(t, fs, "execution.prompts", Warn, "empty")

	f = newFakeServer(t)
	f.acceptAnyToken = true
	f.slowTool = 300 * time.Millisecond
	f.q.readFail = true
	f.q.promptsFail = true
	_, fs = run(t, f, bearer, func(o *Options) {
		o.Only = []string{"net", "discovery", "auth", "handshake", "catalog", "execution"}
		o.CallTimeout = 50 * time.Millisecond
		o.Policy = diagnostics.Policy{Only: []string{"get_time"}}
	})
	expect(t, fs, "execution.tools", Fail, "protocol errors")
	expect(t, fs, "execution.resources", Fail, "failed")
	expect(t, fs, "execution.prompts", Fail, "failed")
	expect(t, fs, "execution.policy", Info, "only get_time")

	f = newFakeServer(t)
	f.acceptAnyToken = true
	s, fs := run(t, f, bearer, func(o *Options) {
		o.Only = []string{"net", "discovery", "auth", "handshake", "catalog", "execution"}
		o.Policy = diagnostics.Policy{Deny: []string{"get_time", "search", "lax"}, AllowDestructive: false}
	})
	expect(t, fs, "execution.tools", Warn, "0 of 4")
	_ = s
	if !strings.Contains(policyDescribe(diagnostics.Policy{AllowDestructive: true, Deny: []string{"x"}}), "ALL tools") {
		t.Error("policyDescribe destructive")
	}
	if !strings.Contains(policyDescribe(diagnostics.Policy{AllowMutations: true}), "mutations") {
		t.Error("policyDescribe mutations")
	}
}

func TestPerformanceAndResilienceBranches(t *testing.T) {
	bearer := &creds.Credentials{Mode: creds.ModeBearer, Token: "tok-1234"}
	// Rate limiting with Retry-After, throttled burst note, and cold/warm info.
	f := newFakeServer(t)
	f.acceptAnyToken = true
	f.rateLimitAfter = 12
	_, fs := run(t, f, bearer, func(o *Options) { o.RPS = 50; o.Samples = 2; o.Concurrency = 4 })
	if v, ok := fs["performance.concurrency"]; !ok || !strings.Contains(v.Detail, "rate-limited") {
		t.Errorf("concurrency = %+v", v)
	}
	expect(t, fs, "performance.throttle", Info, "capped")
	// 429 without Retry-After under --allow-load; and unthrottled with no 429 → warning.
	f = newFakeServer(t)
	f.acceptAnyToken = true
	f.rateLimitAfter = 12
	f.q.noRetryAfter = true
	_, fs = run(t, f, bearer, func(o *Options) { o.AllowLoad = true; o.Concurrency = 4 })
	if v := fs["performance.concurrency"]; v.Status != Warn && !strings.Contains(v.Detail, "429") {
		t.Errorf("no retry-after: %+v", v)
	}
	f = newFakeServer(t)
	f.acceptAnyToken = true
	_, fs = run(t, f, bearer, func(o *Options) { o.AllowLoad = true; o.Concurrency = 2 })
	expect(t, fs, "performance.rate_limit", Warn, "no 429")
	// Errors under concurrency.
	f = newFakeServer(t)
	f.acceptAnyToken = true
	f.q.burstFail = true
	f.q.burstFailAfter = 6
	_, fs = run(t, f, bearer, func(o *Options) { o.Concurrency = 3; o.Samples = 3 })
	if v := fs["performance.concurrency"]; v.Status != Fail || !strings.Contains(v.Detail, "errors") {
		t.Errorf("burst errors: %+v", v)
	}
	// Ping failures and slow tools.
	f = newFakeServer(t)
	f.acceptAnyToken = true
	f.q.pingFail = true
	_, fs = run(t, f, bearer, func(o *Options) {
		o.Only = []string{"net", "discovery", "auth", "handshake", "catalog", "execution", "performance"}
		o.Concurrency = 0
	})
	expect(t, fs, "performance.ping", Fail, "every ping failed")
	f = newFakeServer(t)
	f.acceptAnyToken = true
	f.slowTool = 60 * time.Millisecond
	_, fs = run(t, f, bearer, func(o *Options) {
		o.Only = []string{"net", "discovery", "auth", "handshake", "catalog", "execution", "performance"}
		o.Policy = diagnostics.Policy{Only: []string{"get_time"}}
		o.Samples = 1
		o.Concurrency = 0
	})
	expect(t, fs, "performance.tools", Pass, "1 tools")
	// Resilience: recovery failure when the server starts rejecting everything after the session probe.
	f = newFakeServer(t)
	f.acceptAnyToken = true
	_, fs = run(t, f, bearer, func(o *Options) { o.Only = []string{"net", "discovery", "auth", "handshake", "resilience"} })
	expect(t, fs, "resilience.session_reinit", Pass, "re-initialized")
	f = newFakeServer(t)
	f.acceptAnyToken = true
	f.q.stateless = true
	// Not protected: open server + bearer → token_refresh only runs when auth is required.
	_, fs = run(t, f, &creds.Credentials{Mode: creds.ModeNone}, func(o *Options) { o.Only = []string{"net", "discovery", "auth", "handshake", "resilience"} })
	if _, ok := fs["resilience.token_refresh"]; ok && fs["resilience.token_refresh"].Status != Skip {
		t.Errorf("token refresh should not run: %+v", fs["resilience.token_refresh"])
	}
}

// TestUnauthenticatedToolsNamesTheBlastRadius is the check that turns the
// ecosystem's headline number into something an operator can act on.
//
// "40% of servers expose tools without authentication" is a statistic.
// "anyone can call delete_all on yours" is an incident, and it is the same
// measurement with the catalogue attached.
func TestUnauthenticatedToolsNamesTheBlastRadius(t *testing.T) {
	f := newFakeServer(t)
	// Everything served to everyone: the open server the ecosystem's
	// headline number is about.
	f.q.open = true
	sess, fs := run(t, f, nil, func(o *Options) { o.Only = []string{"net", "discovery", "auth"} })

	got, ok := fs["auth.unauthenticated_tools"]
	if !ok {
		t.Fatal("the check did not run against an open server")
	}
	// The fake's catalogue has one tool with no annotations, which the
	// specification treats as destructive by default. It must be named.
	if !strings.Contains(got.Detail, "delete_all") {
		t.Errorf("the mutating tool is not named: %s", got.Detail)
	}
	// And a read-only tool must not be reported as the danger.
	if strings.Contains(got.Detail, "not declared read-only: get_time") {
		t.Errorf("a read-only tool was counted as mutating: %s", got.Detail)
	}

	// An httptest server is on 127.0.0.1, so this is the loopback case: an
	// open development server is ordinary, and net.scheme already makes the
	// same allowance for plain HTTP.
	if got.Status != Warn || !strings.Contains(got.Detail, "loopback") {
		t.Errorf("on loopback this should warn and say so: %s %q", got.Status, got.Detail)
	}

	// The same server reachable from anywhere else is not ordinary. Only
	// the hostname changes, which is the whole of the distinction.
	sess.URL = &url.URL{Scheme: "https", Host: "mcp.example.com", Path: "/mcp"}
	off := checkUnauthenticatedTools(context.Background(), sess)
	if off.Status != Fail {
		t.Fatalf("off loopback an exposed destructive tool was %s: %s", off.Status, off.Detail)
	}
	if off.Severity != Critical {
		t.Errorf("severity = %s", off.Severity)
	}
	if !strings.Contains(off.Detail, "delete_all") {
		t.Errorf("the mutating tool is not named off loopback: %s", off.Detail)
	}
}

// TestUnauthenticatedToolsWarnsWhenEverythingIsReadOnly: an open catalogue
// of read-only tools is a disclosure problem rather than an incident, and
// treating it as critical would make the check noise on every deliberately
// public server.
func TestUnauthenticatedToolsWarnsWhenEverythingIsReadOnly(t *testing.T) {
	f := newFakeServer(t)
	f.q.open = true
	f.q.readOnlyOnly = true
	sess, fs := run(t, f, nil, func(o *Options) { o.Only = []string{"net", "discovery", "auth"} })

	got := fs["auth.unauthenticated_tools"]
	sess.URL = &url.URL{Scheme: "https", Host: "mcp.example.com", Path: "/mcp"}
	off := checkUnauthenticatedTools(context.Background(), sess)
	for _, f := range []Finding{got, off} {
		if f.Status != Warn {
			t.Errorf("a read-only open catalogue was %s: %s", f.Status, f.Detail)
		}
		if !strings.Contains(f.Detail, "read-only") {
			t.Errorf("the detail does not say why it is only a warning: %s", f.Detail)
		}
	}
}

// TestUnauthenticatedToolsPassesAProtectedServer: the check must not fire
// on a server that does require credentials, or it is noise on every
// correctly configured endpoint.
func TestUnauthenticatedToolsPassesAProtectedServer(t *testing.T) {
	f := newFakeServer(t)
	_, fs := run(t, f, ccCreds(), func(o *Options) { o.Only = []string{"net", "discovery", "auth"} })

	got, ok := fs["auth.unauthenticated_tools"]
	if !ok {
		t.Fatal("the check did not run")
	}
	if got.Status != Pass {
		t.Errorf("a protected server was %s: %s", got.Status, got.Detail)
	}
	if !strings.Contains(got.Detail, "401") && !strings.Contains(got.Detail, "403") {
		t.Errorf("the detail does not say what the server answered: %s", got.Detail)
	}
}

// TestOriginValidation. The fake is on loopback, which is exactly what DNS
// rebinding reaches, so a server that answers a foreign Origin there
// fails; one that refuses it passes, with the status the specification
// names or with another refusal that is still a refusal.
func TestOriginValidation(t *testing.T) {
	bearer := &creds.Credentials{Mode: creds.ModeBearer, Token: "tok-1234"}
	only := func(o *Options) { o.Only = []string{"net", "discovery", "auth", "handshake", "protocol"} }

	f := newFakeServer(t)
	f.acceptAnyToken = true
	_, fs := run(t, f, bearer, only)
	expect(t, fs, "protocol.origin", Pass, "403 for Origin https://passmcp-origin-probe.invalid")

	f = newFakeServer(t)
	f.acceptAnyToken = true
	f.q.originStatus = http.StatusBadRequest
	_, fs = run(t, f, bearer, only)
	expect(t, fs, "protocol.origin", Pass, "asks for 403")

	f = newFakeServer(t)
	f.acceptAnyToken = true
	f.q.originStatus = http.StatusBadGateway
	_, fs = run(t, f, bearer, only)
	expect(t, fs, "protocol.origin", Info, "neither served nor refused")

	f = newFakeServer(t)
	f.acceptAnyToken = true
	f.q.originOpen = true
	_, fs = run(t, f, bearer, only)
	expect(t, fs, "protocol.origin", Fail, "on loopback")
	if got := fs["protocol.origin"]; got.Severity != Major || len(got.Evidence) == 0 {
		t.Errorf("an open loopback server: %+v, want a Major failure citing its request", got)
	}

	// The same server on a public address: still required, not what DNS
	// rebinding reaches, so a warning rather than a failure.
	orig := endpointLocality
	endpointLocality = func(context.Context, string) (string, bool) { return "", false }
	t.Cleanup(func() { endpointLocality = orig })
	f = newFakeServer(t)
	f.acceptAnyToken = true
	f.q.originOpen = true
	_, fs = run(t, f, bearer, only)
	expect(t, fs, "protocol.origin", Warn, "not what DNS rebinding reaches")
}

// TestLocalEndpoint decides the severity, so each branch is pinned.
func TestLocalEndpoint(t *testing.T) {
	ctx := context.Background()
	for host, want := range map[string]string{
		"localhost":   "loopback",
		"127.0.0.1":   "loopback",
		"::1":         "loopback",
		"10.1.2.3":    "a private address",
		"192.168.0.9": "a private address",
		"fe80::1":     "a private address",
	} {
		if got, ok := localEndpoint(ctx, host); !ok || got != want {
			t.Errorf("localEndpoint(%q) = %q %v, want %q", host, got, ok, want)
		}
	}
	for _, host := range []string{"8.8.8.8", "2001:4860:4860::8888", "does-not-resolve.invalid"} {
		if got, ok := localEndpoint(ctx, host); ok {
			t.Errorf("localEndpoint(%q) = %q, want public", host, got)
		}
	}
}

// TestTheRepeatPassIsBoundedAndRepeatable. The slowest tools are always
// repeated, the sample is the same for the same target, and a small
// catalogue is repeated in full.
func TestTheRepeatPassIsBoundedAndRepeatable(t *testing.T) {
	var all []ToolResult
	for i := 0; i < 30; i++ {
		all = append(all, ToolResult{Name: fmt.Sprintf("tool%02d", i), Duration: Millis(time.Duration(i) * time.Millisecond)})
	}
	got := repeatCandidates(all, "https://a.example/mcp")
	if len(got) != repeatSlowest+repeatSampled {
		t.Fatalf("repeated %d of 30", len(got))
	}
	names := map[string]bool{}
	for _, r := range got {
		names[r.Name] = true
	}
	for _, slowest := range []string{"tool29", "tool28", "tool27", "tool26", "tool25"} {
		if !names[slowest] {
			t.Errorf("slow tool %s was not repeated: %v", slowest, names)
		}
	}
	again := repeatCandidates(all, "https://a.example/mcp")
	for i := range got {
		if got[i].Name != again[i].Name {
			t.Fatalf("the same target sampled differently: %v vs %v", got, again)
		}
	}
	if other := repeatCandidates(all, "https://b.example/mcp"); fmt.Sprint(other) == fmt.Sprint(got) {
		t.Error("two targets drew the identical sample; the seed is not used")
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Name > got[i].Name {
			t.Errorf("picks are not in their original order: %v", got)
		}
	}
	if small := repeatCandidates(all[:4], "x"); len(small) != 4 {
		t.Errorf("a small catalogue was sampled: %d", len(small))
	}
}

// TestGetStreamHeldOpen covers a server that answers the GET with an event
// stream and then holds it open and idle, as a conforming server may. The
// check needs only the status and content type; reading the body waited
// out the whole call timeout on every such server.
func TestGetStreamHeldOpen(t *testing.T) {
	bearer := &creds.Credentials{Mode: creds.ModeBearer, Token: "tok-1234"}
	f := newFakeServer(t)
	f.acceptAnyToken = true
	f.q.getStream = true
	f.q.holdStream = true
	const timeout = 5 * time.Second
	start := time.Now()
	_, fs := run(t, f, bearer, func(o *Options) {
		o.Only = []string{"net", "discovery", "auth", "handshake", "protocol"}
		o.CallTimeout = timeout
		// The CLI's client carries the call timeout; without one a read of
		// the held stream would never end and the test would hang, not fail.
		o.HTTPClient = &http.Client{Timeout: timeout, Transport: f.srv.Client().Transport}
	})
	expect(t, fs, "protocol.get_stream", Pass, "event-stream")
	if d := time.Duration(fs["protocol.get_stream"].Duration); d >= timeout/2 {
		t.Errorf("protocol.get_stream took %s: it read the held-open stream instead of stopping at the headers", d)
	}
	if elapsed := time.Since(start); elapsed >= timeout {
		t.Errorf("run took %s, at least one call timeout", elapsed)
	}
}
