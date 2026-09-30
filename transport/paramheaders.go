// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
)

// paramSchema is the part of a tool's inputSchema the binding reads to find
// the arguments it mirrors: the properties chain, and the x-mcp-header name
// on each property.
type paramSchema struct {
	Properties map[string]paramSchema `json:"properties"`
	Header     string                 `json:"x-mcp-header"`
}

// setParamHeaders mirrors the arguments schema annotates with x-mcp-header
// into Mcp-Param-{Name}. The body stays the source of truth, as with
// Mcp-Name. Only strings, booleans and integers are mirrored, only under a
// plain properties chain, and only under a name that is a valid header
// token; anything else is left out rather than guessed, so a server that
// disagrees answers -32020 about the server's own schema, not about a
// header passmcp invented.
func setParamHeaders(h http.Header, schema json.RawMessage, args map[string]json.RawMessage) {
	var s paramSchema
	if json.Unmarshal(schema, &s) != nil {
		return
	}
	walkParams(h, s, args)
}

func walkParams(h http.Header, s paramSchema, args map[string]json.RawMessage) {
	for name, prop := range s.Properties {
		raw, ok := args[name]
		if !ok {
			continue
		}
		if prop.Header != "" && isToken(prop.Header) {
			if v, ok := primitive(raw); ok {
				h.Set(HeaderParamPrefix+prop.Header, EncodeHeaderValue(v))
			}
		}
		if len(prop.Properties) > 0 {
			var nested map[string]json.RawMessage
			if json.Unmarshal(raw, &nested) == nil {
				walkParams(h, prop, nested)
			}
		}
	}
}

// primitive renders a string, a boolean or an integer the way it is
// mirrored, and reports false for anything else, a fractional number
// included.
func primitive(raw json.RawMessage) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return "", false
	}
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return strconv.FormatInt(i, 10), true
		}
	}
	return "", false
}

// isToken reports whether s is an HTTP header field name (RFC 9110 token).
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !tokenChar(s[i]) {
			return false
		}
	}
	return true
}

func tokenChar(c byte) bool {
	switch {
	case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}
