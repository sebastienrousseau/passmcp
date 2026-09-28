// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package auth_test

import (
	"context"
	"fmt"
	"net"

	"satellion.com/passmcp/auth"
)

// A 401 from an MCP server carries the whole of what a client needs to
// start: the scheme, the resource metadata to fetch, and the scopes the
// operation wanted. Parsing it is the first step of the authorization
// state machine.
func ExampleParseWWWAuthenticate() {
	const header = `Bearer realm="mcp", ` +
		`resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", ` +
		`scope="mcp:tools mcp:resources", error="insufficient_scope"`

	for _, c := range auth.ParseWWWAuthenticate(header) {
		fmt.Println("scheme:", c.Scheme)
		fmt.Println("resource_metadata:", c.Params["resource_metadata"])
		fmt.Println("scope:", c.Params["scope"])
		fmt.Println("error:", c.Params["error"])
	}
	// Output:
	// scheme: Bearer
	// resource_metadata: https://mcp.example.com/.well-known/oauth-protected-resource
	// scope: mcp:tools mcp:resources
	// error: insufficient_scope
}

// A server may offer several schemes. Bearer is the one MCP defines, and
// FindBearer picks it out without caring what order they arrived in.
func ExampleFindBearer() {
	challenges := auth.ParseWWWAuthenticate(`Basic realm="legacy", Bearer realm="mcp", scope="mcp:tools"`)

	if bearer, ok := auth.FindBearer(challenges); ok {
		fmt.Println("scope:", bearer.Params["scope"])
	}
	// Output:
	// scope: mcp:tools
}

// Every URL after the operator's own endpoint is chosen by the server
// under test: authorization_servers comes from the resource, token_endpoint
// from the authorization server. URLPolicy is what decides whether a
// discovered URL may be contacted at all, and it refuses plaintext and
// addresses inside your own network unless told otherwise.
func ExampleURLPolicy_Validate() {
	// A resolver that answers without touching the network, so the example
	// is deterministic. In real use, leave Resolver nil.
	policy := auth.URLPolicy{
		Resolver: func(_ context.Context, host string) ([]net.IP, error) {
			if host == "169.254.169.254" {
				return []net.IP{net.ParseIP("169.254.169.254")}, nil
			}
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		},
	}

	for _, u := range []string{
		"https://auth.example.com/token",
		"http://auth.example.com/token",
		"https://169.254.169.254/token",
	} {
		if err := policy.Validate(context.Background(), "token_endpoint", u); err != nil {
			fmt.Printf("refused %s\n", u)
			continue
		}
		fmt.Printf("allowed %s\n", u)
	}
	// Output:
	// allowed https://auth.example.com/token
	// refused http://auth.example.com/token
	// refused https://169.254.169.254/token
}
