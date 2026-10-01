// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package passmcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"satellion.com/passmcp/trace"
	"satellion.com/passmcp/transport"
)

// Initialize starts a fresh session: it clears any session state, sends
// initialize, records the negotiated protocol version, and sends the
// initialized notification.
func (c *Client) Initialize(ctx context.Context) (*InitializeResult, error) {
	c.tr.Reset()
	return c.initialize(trace.Ensure(ctx))
}

func (c *Client) initialize(ctx context.Context) (*InitializeResult, error) {
	params := initializeParams{
		ProtocolVersion: SupportedProtocolVersions[0],
		Capabilities:    ClientCapabilities{},
		ClientInfo:      c.cfg.ClientInfo,
	}
	var res InitializeResult
	if err := c.tr.Call(ctx, "initialize", params, &res); err != nil {
		return nil, err
	}
	if !slices.Contains(SupportedProtocolVersions, res.ProtocolVersion) {
		return nil, fmt.Errorf("passmcp: server negotiated unsupported protocol version %q", res.ProtocolVersion)
	}
	c.tr.SetProtocolVersion(res.ProtocolVersion)
	if err := c.tr.Notify(ctx, "notifications/initialized", nil); err != nil {
		return nil, fmt.Errorf("passmcp: initialized notification: %w", err)
	}
	c.mu.Lock()
	c.init = &res
	c.mu.Unlock()
	return &res, nil
}

// call wraps transport.Call with one automatic re-initialize on session
// expiry.
func (c *Client) call(ctx context.Context, method string, params, result any) error {
	err := c.tr.Call(ctx, method, params, result)
	if errors.Is(err, transport.ErrSessionExpired) {
		if _, ierr := c.initialize(ctx); ierr != nil {
			return fmt.Errorf("passmcp: re-initialize after session expiry: %w", ierr)
		}
		err = c.tr.Call(ctx, method, params, result)
	}
	return err
}

// Call sends an arbitrary JSON-RPC request on the current session.
func (c *Client) Call(ctx context.Context, method string, params, result any) error {
	return c.call(trace.Ensure(ctx), method, params, result)
}

// ListTools returns every tool, following pagination cursors.
func (c *Client) ListTools(ctx context.Context) ([]Tool, error) {
	tools, _, err := c.ListToolsWithHints(ctx)
	return tools, err
}

// ListToolsWithHints is ListTools, and what the server said about caching
// the answer.
//
// A separate method rather than a changed signature: the hints matter to a
// diagnostic and to nothing else, and every existing caller wants the
// catalogue. The hints come from the first page, because that is where a
// server states them and a later page contradicting the first is a server
// problem rather than something to reconcile here.
func (c *Client) ListToolsWithHints(ctx context.Context) ([]Tool, CacheHints, error) {
	ctx = trace.Ensure(ctx)
	var all []Tool
	var hints CacheHints
	cursor := ""
	pg := pager{method: "tools/list"}
	for first := true; ; first = false {
		var page listToolsResult
		if err := c.call(ctx, "tools/list", listToolsParams{Cursor: cursor}, &page); err != nil {
			return nil, CacheHints{}, err
		}
		if first {
			hints = CacheHints{TTLMs: page.TTLMs, Scope: page.CacheScope}
		}
		all = append(all, page.Tools...)
		if page.NextCursor == "" || page.NextCursor == cursor {
			c.rememberTools(all)
			return all, hints, nil
		}
		if err := pg.next(page.NextCursor); err != nil {
			return nil, CacheHints{}, err
		}
		cursor = page.NextCursor
	}
}

// CallTool invokes a tool. A tool-level failure is reported through
// CallToolResult.IsError, not as an error.
func (c *Client) CallTool(ctx context.Context, name string, args any) (*CallToolResult, error) {
	ctx = trace.Ensure(ctx)
	var res CallToolResult
	if err := c.call(ctx, "tools/call", callToolParams{Name: name, Arguments: args}, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// rememberTools hands the listed tools' input schemas to the stateless
// binding, which mirrors x-mcp-header arguments on tools/call. The other
// bindings have no such headers.
func (c *Client) rememberTools(tools []Tool) {
	d, ok := c.tr.Dialect().(*transport.Stateless)
	if !ok {
		return
	}
	schemas := make(map[string]json.RawMessage, len(tools))
	for _, t := range tools {
		schemas[t.Name] = t.InputSchema
	}
	d.RememberTools(schemas)
}
