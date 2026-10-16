// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package telemetry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// observeResponse does everything the recorder does with a response body,
// on ev: it registers the personal values and secrets the body carries,
// copies a JSON-RPC error onto ev.RPC, and, when bodies are captured,
// renders the body for the report. total is the body's size on the wire.
//
// A JSON body is decoded once and every step reads that tree. Registration
// comes first, as it always has: the personal walk before anything is
// masked, the RPC error before masking replaces its "code", and masking,
// which registers secrets, before anything is rendered.
func (r *Recorder) observeResponse(ev *Event, contentType string, body []byte, total int64) {
	red := r.Redactor
	var tree any
	parsed := false
	if looksJSON(body) {
		tree, parsed = decodeJSON(body)
	}
	if parsed {
		red.registerPersonalFromTree(ev.RPC, tree)
	} else {
		red.registerPersonalFromResponse(ev.RPC, body)
	}
	if ev.RPC != nil && len(body) > 0 {
		r.copyRPCError(ev.RPC, body, tree, parsed)
	}
	switch {
	case r.CaptureBodies:
		ev.ResponseBody = r.capture(contentType, body, total, tree, parsed)
	case parsed:
		// Not captured: only the registration of issued secrets is wanted.
		red.maskValue(tree)
	}
}

// copyRPCError copies the JSON-RPC error in a response body, if any, onto
// rpc. When parsed, tree is the body decoded.
func (r *Recorder) copyRPCError(rpc *RPCInfo, body []byte, tree any, parsed bool) {
	var (
		code int
		msg  string
		ok   bool
	)
	if parsed {
		code, msg, ok = rpcErrorFromTree(tree, body)
	} else {
		code, msg, ok = rpcErrorFromBody(body)
	}
	if ok {
		rpc.ErrorCode, rpc.ErrorMessage = code, msg
	}
}

// captureBody renders a body for the report. total is the true size of the
// body on the wire, which may exceed what was retained.
func (r *Recorder) captureBody(contentType string, b []byte, total int64) string {
	return r.capture(contentType, b, total, nil, false)
}

// capture is captureBody for a body that may already be decoded: when
// parsed, tree is b as JSON.
func (r *Recorder) capture(contentType string, b []byte, total int64, tree any, parsed bool) string {
	if len(b) == 0 {
		return ""
	}
	capped := b
	truncated := total > int64(r.BodyCap)
	if len(capped) > r.BodyCap {
		capped = capped[:r.BodyCap]
		parsed = false
	}
	var s string
	switch {
	case strings.HasPrefix(contentType, "application/x-www-form-urlencoded"):
		s = r.Redactor.Form(string(capped))
	case parsed:
		s = r.Redactor.maskedJSON(tree, capped)
	case looksJSON(capped):
		// A truncated body will not parse as JSON, so key-based masking
		// cannot run over it. Fall back to masking by key name on the raw
		// text: a token cut in half is still a token, and the half that
		// survives must not reach a report file.
		s = r.Redactor.JSONOrKeys(capped)
	default:
		s = r.Redactor.String(string(capped))
	}
	// E-mail addresses and phone numbers are masked in every captured
	// body, whatever key or none they sit under (personal.go).
	s = r.Redactor.maskPersonalPatterns(s)
	if truncated {
		s += fmt.Sprintf("…[truncated %d bytes]", total-int64(r.BodyCap))
	}
	return s
}

func rpcErrorFromBody(b []byte) (int, string, bool) {
	// Works for a JSON body; for SSE, find the first data: line.
	if bytes.HasPrefix(bytes.TrimSpace(b), []byte("event:")) || bytes.HasPrefix(bytes.TrimSpace(b), []byte("data:")) {
		for _, line := range bytes.Split(b, []byte("\n")) {
			if bytes.HasPrefix(line, []byte("data:")) {
				b = bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
				break
			}
		}
	}
	var probe struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(b, &probe) != nil || probe.Error == nil {
		return 0, "", false
	}
	return probe.Error.Code, probe.Error.Message, true
}

// rpcErrorFromTree is rpcErrorFromBody for body already decoded as tree,
// and returns what it would. encoding/json matches struct fields without
// regard to case and lets the last matching key win, which a map cannot
// replay, so a document that spells a key in another case is handed to
// rpcErrorFromBody.
func rpcErrorFromTree(tree any, body []byte) (int, string, bool) {
	m, ok := tree.(map[string]any)
	if !ok {
		return 0, "", false
	}
	if hasCaseVariant(m, "error") {
		return rpcErrorFromBody(body)
	}
	e, ok := m["error"].(map[string]any)
	if !ok {
		// Absent, null, or not an object: no error, or a type mismatch.
		return 0, "", false
	}
	if hasCaseVariant(e, "code") || hasCaseVariant(e, "message") {
		return rpcErrorFromBody(body)
	}
	code, ok := rpcErrorCode(e["code"])
	if !ok {
		return 0, "", false
	}
	msg, ok := e["message"].(string)
	if !ok && e["message"] != nil {
		return 0, "", false
	}
	return code, msg, true
}

// rpcErrorCode converts an error's code as json.Unmarshal into an int
// would: null or absent is zero, anything but an integer in range fails.
func rpcErrorCode(v any) (int, bool) {
	switch c := v.(type) {
	case nil:
		return 0, true
	case json.Number:
		n, err := strconv.ParseInt(c.String(), 10, strconv.IntSize)
		return int(n), err == nil
	}
	return 0, false
}

// hasCaseVariant reports whether m has a key other than key that
// encoding/json would match to a field named key.
func hasCaseVariant(m map[string]any, key string) bool {
	for k := range m {
		if k != key && strings.EqualFold(k, key) {
			return true
		}
	}
	return false
}
