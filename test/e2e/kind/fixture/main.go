// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Command fixture is the MCP server the Kubernetes end-to-end test points a
// passmcp fleet at. It is deliberately small and deliberately honest: it
// speaks streamable HTTP behind a bearer token, or stdio, and exposes one
// read-only tool and one destructive one. It is not a reference server and
// is not shipped; it exists so the test can change one thing between runs
// (the read-only tool's readOnlyHint) and see whether the fleet notices.
//
// Tokens are checked either against a static value named by -token-env or
// by RFC 7662 introspection at -introspect, so the client-credentials path
// runs against a real authorization server. With -log-tokens, every bearer
// token received is written to stderr, which is how the test learns the
// tokens the authorization server issued and then proves none of them
// reached passmcp's evidence.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type config struct {
	resource     string
	as           string
	token        string
	introspect   string
	clientID     string
	readOnly     bool
	reflectToken bool
	logTokens    bool
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func main() {
	var (
		listen, cert, key, install, tokenEnv string
		stdio                                bool
		c                                    config
	)
	flag.StringVar(&listen, "listen", ":8443", "address to serve HTTPS on")
	flag.StringVar(&cert, "cert", "/tls/tls.crt", "TLS certificate")
	flag.StringVar(&key, "key", "/tls/tls.key", "TLS key")
	flag.BoolVar(&stdio, "stdio", false, "speak MCP on stdin and stdout instead of HTTP")
	flag.StringVar(&install, "install", "", "copy this binary to the path and exit (the image has no cp)")
	flag.StringVar(&c.resource, "resource", "", "this server's MCP endpoint URL, as clients use it")
	flag.StringVar(&c.as, "as", "", "authorization server issuer to advertise")
	flag.StringVar(&tokenEnv, "token-env", "", "environment variable holding the one accepted bearer token")
	flag.StringVar(&c.introspect, "introspect", "", "RFC 7662 introspection endpoint that decides which tokens are accepted")
	flag.StringVar(&c.clientID, "client-id", "", "with -introspect, the client a token must have been issued to")
	flag.BoolVar(&c.reflectToken, "reflect-token", false, "echo the caller's bearer token in a tool description")
	flag.BoolVar(&c.logTokens, "log-tokens", false, "write every bearer token received to stderr")
	flag.Parse()
	c.readOnly = os.Getenv("FIXTURE_READONLY") != "false"
	if c.clientID == "" {
		c.clientID = os.Getenv("FIXTURE_CLIENT_ID")
	}
	if tokenEnv != "" {
		c.token = os.Getenv(tokenEnv)
	}
	log.SetFlags(log.LstdFlags | log.LUTC)

	var err error
	switch {
	case install != "":
		err = copySelf(install)
	case stdio:
		err = serveStdio(c, os.Stdin, os.Stdout)
	default:
		err = serveHTTP(c, listen, cert, key)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func copySelf(dst string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	b, err := os.ReadFile(self) // #nosec G304 -- our own executable
	if err != nil {
		return err
	}
	// #nosec G306 G703 -- an executable, read-only, written where the pod
	// spec's -install flag says; this is the init container's whole job.
	return os.WriteFile(dst, b, 0o555)
}

func serveStdio(c config, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	enc := json.NewEncoder(out)
	for sc.Scan() {
		var req rpcRequest
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			if err := enc.Encode(rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}}); err != nil {
				return err
			}
			continue
		}
		if resp, ok := dispatch(c, req, ""); ok {
			if err := enc.Encode(resp); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}

func serveHTTP(c config, listen, cert, key string) error {
	mux := http.NewServeMux()
	u, err := url.Parse(c.resource)
	if err != nil {
		return err
	}
	prm := "/.well-known/oauth-protected-resource" + u.Path
	mux.HandleFunc(prm, c.metadata)
	mux.HandleFunc("/.well-known/oauth-protected-resource", c.metadata)
	mux.HandleFunc(u.Path, func(w http.ResponseWriter, r *http.Request) { c.mcp(w, r, u.Scheme+"://"+u.Host+prm) })
	srv := &http.Server{Addr: listen, Handler: logRequests(mux), ReadHeaderTimeout: 10 * time.Second}
	log.Printf("serving %s (readOnlyHint on lookup: %t)", c.resource, c.readOnly)
	return srv.ListenAndServeTLS(cert, key)
}

func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// #nosec G706 -- every field is %q-quoted, so no value can start a new log line
		log.Printf("request %q %q host=%q ua=%q", r.Method, r.URL.Path, r.Host, r.UserAgent())
		h.ServeHTTP(w, r)
	})
}

func (c config) metadata(w http.ResponseWriter, _ *http.Request) {
	md := map[string]any{
		"resource":                 c.resource,
		"bearer_methods_supported": []string{"header"},
	}
	if c.as != "" {
		md["authorization_servers"] = []string{c.as}
	}
	writeJSON(w, http.StatusOK, md)
}

func (c config) mcp(w http.ResponseWriter, r *http.Request, prm string) {
	// No browser has any business here: a request that carries an Origin
	// is refused, as the Streamable HTTP transport requires.
	if r.Header.Get("Origin") != "" {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if c.logTokens && ok && tok != "" {
		// #nosec G706 -- logging the token is this flag's purpose: the test
		// reads it back to prove passmcp's evidence never contains it. Quoted,
		// so it cannot start a new log line.
		log.Printf("bearer-token-seen %q", tok)
	}
	if !ok || !c.accepts(r, tok) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata=%q`, prm))
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req rpcRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}})
		return
	}
	reflected := ""
	if c.reflectToken {
		reflected = tok
	}
	resp, ok := dispatch(c, req, reflected)
	if !ok {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (c config) accepts(r *http.Request, tok string) bool {
	if tok == "" {
		return false
	}
	if c.introspect == "" {
		return c.token != "" && tok == c.token
	}
	form := url.Values{"token": {tok}}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, c.introspect, strings.NewReader(form.Encode()))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("introspection failed: %v", err)
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	var in struct {
		Active   bool   `json:"active"`
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&in); err != nil {
		return false
	}
	log.Printf("introspected: active=%t client_id=%s", in.Active, in.ClientID)
	return in.Active && (c.clientID == "" || in.ClientID == c.clientID)
}

// dispatch answers one JSON-RPC message. It reports false for a
// notification, which gets no response.
func dispatch(c config, req rpcRequest, reflected string) (rpcResponse, bool) {
	if len(req.ID) == 0 {
		return rpcResponse{}, false
	}
	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		resp.Result = initialize(req.Params)
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = map[string]any{"tools": tools(c, reflected)}
	case "tools/call":
		result, err := call(req.Params)
		if err != nil {
			resp.Error = &rpcError{-32602, err.Error()}
		} else {
			resp.Result = result
		}
	default:
		resp.Error = &rpcError{-32601, "method not found"}
	}
	return resp, true
}

func initialize(params json.RawMessage) map[string]any {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p)
	v := p.ProtocolVersion
	if v == "" {
		v = "2025-06-18"
	}
	return map[string]any{
		"protocolVersion": v,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]string{"name": "passmcp-e2e-fixture", "version": "0.0.9"},
	}
}

func tools(c config, reflected string) []map[string]any {
	desc := "Look up a record by its identifier and return it."
	if reflected != "" {
		desc += " Authorised as " + reflected + "."
	}
	return []map[string]any{
		{
			"name":        "lookup",
			"title":       "Look up a record",
			"description": desc,
			"inputSchema": map[string]any{
				"type":                 "object",
				"properties":           map[string]any{"id": map[string]any{"type": "string", "maxLength": 64, "description": "record identifier"}},
				"required":             []string{"id"},
				"additionalProperties": false,
			},
			"annotations": map[string]any{"readOnlyHint": c.readOnly, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false},
		},
		{
			"name":        "delete_record",
			"title":       "Delete a record",
			"description": "Delete a record by its identifier. This cannot be undone.",
			"inputSchema": map[string]any{
				"type":                 "object",
				"properties":           map[string]any{"id": map[string]any{"type": "string", "maxLength": 64, "description": "record identifier"}},
				"required":             []string{"id"},
				"additionalProperties": false,
			},
			"annotations": map[string]any{"readOnlyHint": false, "destructiveHint": true, "idempotentHint": true, "openWorldHint": false},
		},
	}
}

func call(params json.RawMessage) (map[string]any, error) {
	var p struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, errors.New("invalid params")
	}
	switch p.Name {
	case "lookup":
		id, ok := p.Arguments["id"]
		if !ok {
			return nil, errors.New("missing required argument: id")
		}
		if len(id) > 64 {
			id = id[:64]
		}
		return map[string]any{"content": []map[string]string{{"type": "text", "text": "record " + id + ": not found"}}}, nil
	case "delete_record":
		if _, ok := p.Arguments["id"]; !ok {
			return nil, errors.New("missing required argument: id")
		}
		return map[string]any{"isError": true, "content": []map[string]string{{"type": "text", "text": "refused: this fixture deletes nothing"}}}, nil
	default:
		return nil, fmt.Errorf("unknown tool %q", p.Name)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
