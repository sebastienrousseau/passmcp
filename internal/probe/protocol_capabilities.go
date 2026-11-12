// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"encoding/json"
	"fmt"

	"satellion.com/passmcp/transport"
)

const probeMissingResourceURI = "passmcp://no-such-resource"

// capabilitySkip reports why a capability-specific protocol probe cannot run,
// or ("", false) when the server declared the capability.
//
// Probing an optional capability the server never claimed produces either a
// false failure or a thin-shadow pass on -32601 Method not found (violating
// ADR-0002).
func (s *Session) capabilitySkip(declared bool, name string) (string, bool) {
	if s.Init == nil {
		return "handshake did not run, so declared capabilities are unknown", true
	}
	if s.Stateless() && (s.Era == nil || s.Era.Discovered == nil) {
		return "server/discover did not answer, so declared capabilities are unknown", true
	}
	if !declared {
		return "the server does not declare the " + name + " capability", true
	}
	return "", false
}

// probeInvalidParams is the protocol.invalid_params verdict: a tools/call
// with no name is rejected.
func probeInvalidParams(s *Session, raw rawProbe) Finding {
	c := s.check("protocol.invalid_params", "tools/call without a name is rejected")
	if why, skip := s.capabilitySkip(s.Init != nil && s.Init.Capabilities.Tools != nil, "tools"); skip {
		return c.skip(why)
	}
	id := s.nextID()
	rep, err := raw("invalid params", rawSend{Request: &transport.Request{JSONRPC: "2.0", ID: &id, Method: "tools/call", Params: json.RawMessage(`{}`)}})
	switch {
	case err != nil:
		return c.warn("request failed: "+err.Error(), "")
	case rep.Response != nil && rep.Response.Error != nil:
		if rep.Response.Error.Code == -32602 {
			return c.pass("-32602 Invalid params")
		}
		return c.info(fmt.Sprintf("error %d: %s", rep.Response.Error.Code, rep.Response.Error.Message))
	case rep.HTTP && rep.Status >= 400:
		return c.info(fmt.Sprintf("HTTP %d", rep.Status))
	default:
		return c.fail(Minor, "a tools/call with no name succeeded", "validate params and return -32602")
	}
}

// probeUnknownTool is the protocol.unknown_tool verdict: calling a tool
// that does not exist is reported as an error.
func probeUnknownTool(s *Session, pctx func(string) context.Context) Finding {
	c := s.check("protocol.unknown_tool", "Unknown tool is reported")
	if why, skip := s.capabilitySkip(s.Init != nil && s.Init.Capabilities.Tools != nil, "tools"); skip {
		return c.skip(why)
	}
	res, err := s.Client.CallTool(pctx("unknown tool"), "passmcp_no_such_tool", map[string]any{})
	switch {
	case err != nil:
		var rpc *transport.RPCError
		if asRPC(err, &rpc) {
			return c.pass(fmt.Sprintf("JSON-RPC error %d", rpc.Code))
		}
		return c.warn(err.Error(), "")
	case res.IsError:
		return c.pass("isError result: " + truncate(res.Text(), 80))
	default:
		return c.fail(Major, "calling a non-existent tool returned success", "return -32602 or an isError result")
	}
}

// probeUnknownResource is the protocol.unknown_resource verdict: reading a
// resource URI that does not exist returns a JSON-RPC error (SEP-2164).
func probeUnknownResource(s *Session, pctx func(string) context.Context) Finding {
	c := s.check("protocol.unknown_resource", "Unknown resource URI is rejected")
	if why, skip := s.capabilitySkip(s.Init != nil && s.Init.Capabilities.Resources != nil, "resources"); skip {
		return c.skip(why)
	}
	_, err := s.Client.ReadResource(pctx("unknown resource"), probeMissingResourceURI)
	if err == nil {
		return c.fail(Major, "reading a non-existent resource URI returned contents",
			"return JSON-RPC error -32602 (Invalid params) with error.data.uri naming the missing URI")
	}
	var rpc *transport.RPCError
	if !asRPC(err, &rpc) {
		return c.warn("request failed: "+err.Error(), "")
	}
	if s.Stateless() {
		return statelessUnknownResource(c, rpc)
	}
	if rpc.Code == -32002 || rpc.Code == -32602 {
		return c.pass(fmt.Sprintf("JSON-RPC error %d", rpc.Code))
	}
	return c.warn(fmt.Sprintf("JSON-RPC error %d (%s); -32002 or -32602 expected", rpc.Code, truncate(rpc.Message, 80)),
		"return -32002 or -32602 when a resource URI does not exist")
}

func statelessUnknownResource(c *check, rpc *transport.RPCError) Finding {
	switch rpc.Code {
	case -32602:
		if errorDataURI(rpc.Data) == probeMissingResourceURI {
			return c.pass("-32602 Invalid params with error.data.uri")
		}
		return c.warn("-32602 Invalid params without error.data.uri echoing the requested URI",
			"include data: {\"uri\": <requested>} on -32602 responses from resources/read (SEP-2164)")
	case -32002:
		return c.warn("returned retired error -32002; 2026-07-28 standardized unknown resources on -32602 (SEP-2164)",
			"return -32602 (Invalid params) with error.data.uri instead of -32002 on 2026-07-28")
	default:
		return c.warn(fmt.Sprintf("JSON-RPC error %d (%s); -32602 expected", rpc.Code, truncate(rpc.Message, 80)),
			"return -32602 (Invalid params) with error.data.uri for an unknown resource URI")
	}
}

func errorDataURI(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var d struct {
		URI string `json:"uri"`
	}
	if json.Unmarshal(raw, &d) != nil {
		return ""
	}
	return d.URI
}
