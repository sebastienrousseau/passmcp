// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// supportedVersions are the protocol revisions the server negotiates,
// newest first.
var supportedVersions = []string{"2025-11-25", "2025-06-18"}

// maxBody bounds a request body. The server is a demonstration, but one that
// reads without a limit would be a flaw nobody chose.
const maxBody = 1 << 20

// rpcRequest is the part of a JSON-RPC message the server reads.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// rpcError is a JSON-RPC error object.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// server is one Streamable HTTP MCP endpoint carrying at most one flaw.
type server struct {
	flaw     string
	mu       sync.Mutex
	sessions map[string]bool
}

// newServer returns the handler for flaw, which must be in Flaws.
func newServer(flaw string) http.Handler {
	return &server{flaw: flaw, sessions: map[string]bool{}}
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.originAllowed(r) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodPost:
		s.post(w, r)
	case http.MethodDelete:
		s.forget(r.Header.Get("Mcp-Session-Id"))
		w.WriteHeader(http.StatusNoContent)
	default:
		// No server-initiated stream: the specification lets a server say so.
		w.Header().Set("Allow", "POST, DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// originAllowed rejects a browser Origin that is not this machine, which is
// what the specification asks of every Streamable HTTP server.
func (s *server) originAllowed(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" || s.flaw == "any-origin" {
		return true
	}
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	h := u.Hostname()
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func (s *server) post(w http.ResponseWriter, r *http.Request) {
	if !accepts(r.Header.Get("Accept")) {
		writeError(w, http.StatusNotAcceptable, nil, -32600, "Accept must list application/json and text/event-stream")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		writeError(w, http.StatusBadRequest, nil, -32700, "unreadable body")
		return
	}
	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		if s.flaw == "accepts-malformed-json" {
			writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": nil, "result": map[string]any{}})
			return
		}
		writeError(w, http.StatusBadRequest, nil, -32700, "parse error")
		return
	}
	if req.Method == "initialize" {
		s.initialize(w, req)
		return
	}
	if msg := s.admit(r); msg != "" {
		status := http.StatusBadRequest
		if strings.HasPrefix(msg, "unknown session") {
			status = http.StatusNotFound
		}
		writeError(w, status, req.ID, -32600, msg)
		return
	}
	s.dispatch(w, req)
}

// accepts reports whether an Accept header lists both types a Streamable
// HTTP client must accept.
func accepts(h string) bool {
	h = strings.ToLower(h)
	return strings.Contains(h, "*/*") ||
		(strings.Contains(h, "application/json") && strings.Contains(h, "text/event-stream"))
}

// admit checks the session and protocol-version headers every request after
// initialize carries, returning why it is refused or "".
func (s *server) admit(r *http.Request) string {
	id := r.Header.Get("Mcp-Session-Id")
	if id == "" {
		return "missing Mcp-Session-Id"
	}
	s.mu.Lock()
	known := s.sessions[id]
	s.mu.Unlock()
	if !known {
		return "unknown session " + id
	}
	if v := r.Header.Get("MCP-Protocol-Version"); v != "" && !supported(v) {
		return "unsupported MCP-Protocol-Version " + v
	}
	return ""
}

func supported(v string) bool {
	for _, s := range supportedVersions {
		if s == v {
			return true
		}
	}
	return false
}

func (s *server) initialize(w http.ResponseWriter, req rpcRequest) {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(req.Params, &p)
	version := supportedVersions[0]
	if supported(p.ProtocolVersion) {
		version = p.ProtocolVersion
	}
	id := newSessionID()
	s.mu.Lock()
	s.sessions[id] = true
	s.mu.Unlock()
	w.Header().Set("Mcp-Session-Id", id)
	s.result(w, req.ID, map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
		"serverInfo":      map[string]any{"name": "passmcp-example-" + s.flaw, "version": "0.0.1"},
		"instructions":    "A demonstration server for passmcp. Its dictionary tool looks up English words.",
	})
}

func (s *server) forget(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

func newSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// dispatch answers every method after initialize.
func (s *server) dispatch(w http.ResponseWriter, req rpcRequest) {
	if len(req.ID) == 0 {
		// A notification: acknowledged, never answered.
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch req.Method {
	case "ping":
		s.result(w, req.ID, map[string]any{})
	case "tools/list":
		s.result(w, req.ID, map[string]any{"tools": tools(s.flaw)})
	case "tools/call":
		s.call(w, req)
	default:
		writeError(w, http.StatusOK, req.ID, -32601, "method not found: "+req.Method)
	}
}

// result writes a successful response, with the wrong id when that is the
// flaw.
func (s *server) result(w http.ResponseWriter, id json.RawMessage, v any) {
	if s.flaw == "wrong-id" {
		id = json.RawMessage("987654321")
	}
	writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": id, "result": v})
}

func writeError(w http.ResponseWriter, status int, id json.RawMessage, code int, msg string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	writeJSON(w, status, map[string]any{"jsonrpc": "2.0", "id": id, "error": rpcError{code, msg}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// A write error means the client went away; there is nobody to tell.
	_ = json.NewEncoder(w).Encode(v)
}
