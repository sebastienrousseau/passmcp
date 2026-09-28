// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package passmcp

import (
	"context"
	"encoding/json"

	"satellion.com/passmcp/trace"
)

// Resource is one entry from resources/list.
type Resource struct {
	URI         string          `json:"uri"`
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description,omitempty"`
	MimeType    string          `json:"mimeType,omitempty"`
	Size        int64           `json:"size,omitempty"`
	Annotations json.RawMessage `json:"annotations,omitempty"`
}

// ResourceTemplate is one entry from resources/templates/list.
type ResourceTemplate struct {
	URITemplate string `json:"uriTemplate"`
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// ResourceContents is one item in a resources/read result.
type ResourceContents struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
	Blob     string `json:"blob,omitempty"`
}

// ReadResourceResult is the result of resources/read.
type ReadResourceResult struct {
	Contents []ResourceContents `json:"contents"`
}

// PromptArgument describes one prompt parameter.
type PromptArgument struct {
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// Prompt is one entry from prompts/list.
type Prompt struct {
	Name        string           `json:"name"`
	Title       string           `json:"title,omitempty"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
}

// PromptMessage is one message in a prompts/get result.
type PromptMessage struct {
	Role    string  `json:"role"`
	Content Content `json:"content"`
}

// GetPromptResult is the result of prompts/get.
type GetPromptResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
}

type cursorParams struct {
	Cursor string `json:"cursor,omitempty"`
}

// Ping sends the MCP ping request.
func (c *Client) Ping(ctx context.Context) error {
	return c.call(trace.Ensure(ctx), "ping", nil, nil)
}

// ListResources returns every resource, following pagination.
func (c *Client) ListResources(ctx context.Context) ([]Resource, error) {
	ctx = trace.Ensure(ctx)
	var all []Resource
	cursor := ""
	for {
		var page struct {
			Resources  []Resource `json:"resources"`
			NextCursor string     `json:"nextCursor,omitempty"`
		}
		if err := c.call(ctx, "resources/list", cursorParams{Cursor: cursor}, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Resources...)
		if page.NextCursor == "" || page.NextCursor == cursor {
			return all, nil
		}
		cursor = page.NextCursor
	}
}

// ListResourceTemplates returns every resource template, following pagination.
func (c *Client) ListResourceTemplates(ctx context.Context) ([]ResourceTemplate, error) {
	ctx = trace.Ensure(ctx)
	var all []ResourceTemplate
	cursor := ""
	for {
		var page struct {
			Templates  []ResourceTemplate `json:"resourceTemplates"`
			NextCursor string             `json:"nextCursor,omitempty"`
		}
		if err := c.call(ctx, "resources/templates/list", cursorParams{Cursor: cursor}, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Templates...)
		if page.NextCursor == "" || page.NextCursor == cursor {
			return all, nil
		}
		cursor = page.NextCursor
	}
}

// ReadResource reads one resource by URI.
func (c *Client) ReadResource(ctx context.Context, uri string) (*ReadResourceResult, error) {
	var res ReadResourceResult
	if err := c.call(trace.Ensure(ctx), "resources/read", map[string]string{"uri": uri}, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// ListPrompts returns every prompt, following pagination.
func (c *Client) ListPrompts(ctx context.Context) ([]Prompt, error) {
	ctx = trace.Ensure(ctx)
	var all []Prompt
	cursor := ""
	for {
		var page struct {
			Prompts    []Prompt `json:"prompts"`
			NextCursor string   `json:"nextCursor,omitempty"`
		}
		if err := c.call(ctx, "prompts/list", cursorParams{Cursor: cursor}, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Prompts...)
		if page.NextCursor == "" || page.NextCursor == cursor {
			return all, nil
		}
		cursor = page.NextCursor
	}
}

// GetPrompt renders one prompt with arguments.
func (c *Client) GetPrompt(ctx context.Context, name string, args map[string]string) (*GetPromptResult, error) {
	var res GetPromptResult
	params := map[string]any{"name": name}
	if len(args) > 0 {
		params["arguments"] = args
	}
	if err := c.call(trace.Ensure(ctx), "prompts/get", params, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
