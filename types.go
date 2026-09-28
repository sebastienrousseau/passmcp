// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package passmcp is a Model Context Protocol client for onboarding and
// validating remote MCP servers over Streamable HTTP with OAuth 2.1.
//
// The Client drives the full authorization state machine: it contacts the
// server, honours a 401 challenge by discovering protected-resource and
// authorization-server metadata, registers a client identity, obtains a
// token with either the client-credentials (B2B) or authorization-code with
// PKCE (B2C) grant, and completes the MCP initialize handshake.
package passmcp

import "encoding/json"

// SupportedProtocolVersions lists the protocol versions this client can
// speak, newest first. The first entry is offered on initialize; a server
// may answer with any listed version.
var SupportedProtocolVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26"}

// Implementation identifies a client or server.
type Implementation struct {
	Name    string `json:"name"`
	Title   string `json:"title,omitempty"`
	Version string `json:"version"`
}

// ClientCapabilities advertised on initialize.
type ClientCapabilities struct {
	Roots *struct {
		ListChanged bool `json:"listChanged,omitempty"`
	} `json:"roots,omitempty"`
	Sampling    *struct{} `json:"sampling,omitempty"`
	Elicitation *struct{} `json:"elicitation,omitempty"`
}

// ServerCapabilities as reported by the server on initialize.
type ServerCapabilities struct {
	Tools *struct {
		ListChanged bool `json:"listChanged,omitempty"`
	} `json:"tools,omitempty"`
	Resources *struct {
		Subscribe   bool `json:"subscribe,omitempty"`
		ListChanged bool `json:"listChanged,omitempty"`
	} `json:"resources,omitempty"`
	Prompts *struct {
		ListChanged bool `json:"listChanged,omitempty"`
	} `json:"prompts,omitempty"`
	Logging *struct{} `json:"logging,omitempty"`
}

type initializeParams struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ClientCapabilities `json:"capabilities"`
	ClientInfo      Implementation     `json:"clientInfo"`
}

// InitializeResult is the server's answer to initialize.
type InitializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      Implementation     `json:"serverInfo"`
	Instructions    string             `json:"instructions,omitempty"`
}

// ToolAnnotations are hints about tool behaviour. All are advisory; the
// spec defaults are readOnlyHint=false, destructiveHint=true,
// idempotentHint=false, openWorldHint=true.
type ToolAnnotations struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    *bool  `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool  `json:"destructiveHint,omitempty"`
	IdempotentHint  *bool  `json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool  `json:"openWorldHint,omitempty"`
}

// Tool is one entry from tools/list.
type Tool struct {
	Name         string           `json:"name"`
	Title        string           `json:"title,omitempty"`
	Description  string           `json:"description,omitempty"`
	InputSchema  json.RawMessage  `json:"inputSchema"`
	OutputSchema json.RawMessage  `json:"outputSchema,omitempty"`
	Annotations  *ToolAnnotations `json:"annotations,omitempty"`
}

// IsReadOnly reports the effective readOnlyHint (default false).
func (t Tool) IsReadOnly() bool {
	return t.Annotations != nil && t.Annotations.ReadOnlyHint != nil && *t.Annotations.ReadOnlyHint
}

// IsDestructive reports the effective destructiveHint (default true). A
// read-only tool is never destructive.
func (t Tool) IsDestructive() bool {
	if t.IsReadOnly() {
		return false
	}
	if t.Annotations == nil || t.Annotations.DestructiveHint == nil {
		return true
	}
	return *t.Annotations.DestructiveHint
}

type listToolsParams struct {
	Cursor string `json:"cursor,omitempty"`
}

type listToolsResult struct {
	Tools      []Tool `json:"tools"`
	NextCursor string `json:"nextCursor,omitempty"`
	// The 2026-07-28 revision makes every list result cacheable: ttlMs is
	// how long a client MAY keep it and cacheScope is whether that cache
	// may be shared. Both are optional, and both are how a server tells a
	// client to stop re-fetching a catalogue it already has.
	TTLMs      *int   `json:"ttlMs,omitempty"`
	CacheScope string `json:"cacheScope,omitempty"`
}

// CacheHints are what a list result said about being cached.
//
// A catalogue is re-fetched by every client on every session, and a large
// one is paid for in context on every call after that. These two fields
// are the protocol's own answer to that cost, which makes their absence
// worth reporting on a catalogue big enough for it to matter.
type CacheHints struct {
	// TTLMs is how long a client may cache the result, or nil when the
	// server said nothing.
	TTLMs *int `json:"ttl_ms,omitempty"`
	// Scope is "public" or "private", or empty when unsaid.
	Scope string `json:"cache_scope,omitempty"`
}

// Stated reports whether the server said anything about caching at all.
func (c CacheHints) Stated() bool { return c.TTLMs != nil || c.Scope != "" }

type callToolParams struct {
	Name      string `json:"name"`
	Arguments any    `json:"arguments,omitempty"`
}

// Content is one content block in a tool result.
type Content struct {
	Type     string          `json:"type"`
	Text     string          `json:"text,omitempty"`
	Data     string          `json:"data,omitempty"`
	MimeType string          `json:"mimeType,omitempty"`
	Resource json.RawMessage `json:"resource,omitempty"`
}

// CallToolResult is the result of tools/call. IsError marks a tool-level
// failure (as opposed to a protocol error, which is returned as a Go
// error). StructuredContent, when present, must validate against the
// tool's OutputSchema.
type CallToolResult struct {
	Content           []Content       `json:"content"`
	StructuredContent json.RawMessage `json:"structuredContent,omitempty"`
	IsError           bool            `json:"isError,omitempty"`
}

// Text concatenates all text content blocks.
func (r *CallToolResult) Text() string {
	var s string
	for _, c := range r.Content {
		if c.Type == "text" {
			if s != "" {
				s += "\n"
			}
			s += c.Text
		}
	}
	return s
}
