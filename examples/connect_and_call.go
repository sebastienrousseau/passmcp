// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build ignore

// connect_and_call connects to an MCP server with OAuth client credentials
// and invokes one tool, using only the public packages.
//
//	go run examples/connect_and_call.go https://mcp.example.com/mcp search
package main

import (
	"context"
	"fmt"
	"net/url"
	"os"

	"satellion.com/passmcp"
	"satellion.com/passmcp/auth"
	"satellion.com/passmcp/trace"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: connect_and_call <endpoint> <tool>")
		os.Exit(2)
	}
	client, err := passmcp.New(passmcp.Config{
		Endpoint: os.Args[1],
		Auth: passmcp.AuthConfig{
			Mode:         passmcp.AuthClientCredentials,
			Registration: auth.RegistrationOptions{StaticClientID: os.Getenv("PASSMCP_CLIENT_ID"), StaticClientSecret: os.Getenv("PASSMCP_CLIENT_SECRET")},
			Extra:        url.Values{"profile_id": {os.Getenv("PROFILE_ID")}},
		},
	})
	if err != nil {
		fail(err)
	}
	ctx := trace.Ensure(context.Background())
	res, err := client.Connect(ctx) // 200 → connected; 401 → discovery, token, initialize
	if err != nil {
		fail(err)
	}
	fmt.Printf("connected to %s %s over protocol %s\n", res.Initialize.ServerInfo.Name, res.Initialize.ServerInfo.Version, res.Initialize.ProtocolVersion)
	out, err := client.CallTool(ctx, os.Args[2], map[string]any{})
	if err != nil {
		fail(err)
	}
	fmt.Printf("isError=%t text=%q\n", out.IsError, out.Text())
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
