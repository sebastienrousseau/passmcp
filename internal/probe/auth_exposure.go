// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/telemetry"
	"satellion.com/passmcp/transport"
)

// The measured headline of this ecosystem is that 40.55% of live remote MCP
// servers expose tools with no authentication at all. passmcp could already
// tell an operator that their server answered an unauthenticated request —
// discovery.first_contact says exactly that — and it could not tell them the
// only thing that makes the number actionable: *which* tools, and whether any
// of them changes something.
//
// "Your server is open" is a posture. "Anyone on the internet can call
// delete_customer on your server" is an incident, and it is the same
// measurement with the catalogue attached.

// unauthenticatedListing is what the credential-free transport got back.
type unauthenticatedListing struct {
	// Status is the HTTP status of the request that mattered: the
	// initialize for a handshake-era server, or the tools/list itself.
	Status int
	Tools  []passmcp.Tool
	// Unreadable records a 200 whose body could not be parsed as a tool
	// list. It is kept separate from an empty catalogue because the two mean
	// opposite things — "there is nothing here" against "there is something
	// here and passmcp could not read it" — and reporting the second as the
	// first would be the comfortable mistake.
	Unreadable bool
}

// answered reports whether an exchange produced a usable JSON-RPC result.
//
// A named predicate rather than the condition inline: `raw.Response.Error`
// beside a `return nil` reads to a linter, and to a human skimming, as an
// error being swallowed. It is not one — it is the server's own error object,
// which is an answer.
func answered(raw *transport.RawResult) bool {
	return raw.Status == http.StatusOK && raw.Response != nil && raw.Response.Error == nil
}

// listToolsUnauthenticated asks for the catalogue over the bare transport,
// which carries no token, no API-key headers and no basic auth.
//
// Which request that is depends on the generation, exactly as first contact
// does: the stateless revision answers tools/list directly, and a
// handshake-era server needs an initialize first or it will refuse for a
// reason that has nothing to do with authorization. Reading that refusal as
// "protected" would be the comfortable mistake.
func (s *Session) listToolsUnauthenticated(ctx context.Context) (*unauthenticatedListing, error) {
	tr := s.Bare
	if tr == nil {
		return nil, fmt.Errorf("no credential-free transport")
	}
	cctx := telemetry.WithPhase(ctx, "auth", "unauthenticated catalogue")

	if !s.Stateless() {
		// The session this returns is deliberately kept: without it the
		// tools/list that follows is refused for the wrong reason.
		id := tr.NextID()
		raw, err := tr.Do(cctx, transport.RawOptions{
			Request:     &transport.Request{JSONRPC: "2.0", ID: &id, Method: "initialize", Params: json.RawMessage(initParams(s))},
			OmitSession: true,
		})
		if err != nil {
			return nil, err
		}
		if !answered(raw) {
			return &unauthenticatedListing{Status: raw.Status}, nil
		}
	}

	id := tr.NextID()
	raw, err := tr.Do(cctx, transport.RawOptions{
		Request: &transport.Request{JSONRPC: "2.0", ID: &id, Method: "tools/list", Params: json.RawMessage(`{}`)},
	})
	if err != nil {
		return nil, err
	}
	out := &unauthenticatedListing{Status: raw.Status}
	if !answered(raw) {
		return out, nil
	}
	var result struct {
		Tools []passmcp.Tool `json:"tools"`
	}
	// The parse outcome is the finding, not an error to propagate: the
	// server answered, and whether passmcp could read the answer is a fact
	// about the answer. Recorded as state rather than returned as an error
	// so the caller keeps the status it needs to report.
	out.Unreadable = json.Unmarshal(raw.Response.Result, &result) != nil
	if out.Unreadable {
		return out, nil
	}
	out.Tools = result.Tools
	return out, nil
}

// checkUnauthenticatedTools names the blast radius of an open server.
func checkUnauthenticatedTools(ctx context.Context, s *Session) Finding {
	c := s.check("auth.unauthenticated_tools", "Tools reachable without credentials")

	if s.overStdio() {
		return c.skip("a child process has no credentials to omit: whoever can run the command can call its tools")
	}
	if s.Bare == nil || !s.Reached {
		return c.skip("the server was never reached without credentials")
	}

	listing, err := s.listToolsUnauthenticated(ctx)
	if err != nil {
		return c.info("could not ask without credentials: " + truncate(err.Error(), 120))
	}

	switch listing.Status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return c.pass(fmt.Sprintf("HTTP %d: the catalogue is not served without credentials", listing.Status))
	}
	if listing.Status != http.StatusOK {
		return c.info(fmt.Sprintf("HTTP %d to an unauthenticated tools/list", listing.Status))
	}
	switch {
	case listing.Unreadable:
		// Not a pass. The server served something to an unauthenticated
		// caller and passmcp could not read it, which is a smaller finding
		// than an exposed catalogue and a larger one than a refusal.
		return c.warn("an unauthenticated tools/list was answered with a body that is not a tool list",
			"the endpoint answers an unauthenticated request; whether it exposes tools could not be determined from the reply")
	case len(listing.Tools) == 0:
		return c.pass("an unauthenticated tools/list returned no tools")
	}

	var mutating, readOnly []string
	for _, t := range listing.Tools {
		if t.IsReadOnly() {
			readOnly = append(readOnly, t.Name)
			continue
		}
		mutating = append(mutating, t.Name)
	}

	// A server that advertised authorization and then served the catalogue
	// anyway is a different, worse finding than one that never claimed to
	// protect anything: somebody believes this endpoint is protected.
	lead := fmt.Sprintf("%s callable with no credentials", plural(len(listing.Tools), "tool"))
	if s.RequiresAuth {
		lead = fmt.Sprintf("the server answers 401 to first contact and still served %s to an unauthenticated tools/list",
			plural(len(listing.Tools), "tool"))
	}

	if len(mutating) == 0 {
		return c.ev(list(readOnly)).warn(
			lead+", all of them read-only",
			"an open catalogue still discloses what the system does — tool names and descriptions map your internal capabilities for anyone who asks")
	}

	detail := fmt.Sprintf("%s; %s not declared read-only: %s",
		lead, plural(len(mutating), "tool"), list(mutating))
	advice := "require authorization before tools/list and before tools/call. A tool that is not declared readOnlyHint:true is destructive by the specification's own default, and this one can be invoked by anyone who can reach the endpoint"

	// Loopback is where an open server is ordinary rather than alarming,
	// and net.scheme already makes the same allowance for plain HTTP. The
	// finding is still made, because a development server reached over a
	// tunnel is not a development server any more.
	if s.URL != nil && isLoopback(s.URL.Hostname()) {
		return c.ev(list(mutating)).warn(detail+" (loopback)",
			advice+". On loopback this is ordinary; it stops being ordinary the moment the endpoint is reachable from anywhere else")
	}
	return c.ev(list(mutating)).fail(Critical, detail, advice)
}
