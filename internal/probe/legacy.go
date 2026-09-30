// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/telemetry"
	"satellion.com/passmcp/transport"
)

// Older revisions are graded, not refused.
//
// The specification's version negotiation lets a server answer initialize
// with the revision it speaks, and a client that can speak it carries on.
// passmcp can speak 2024-11-05, and a large share of stdio servers still
// do. What it cannot do is grade such a server on fields its revision does
// not have: a check that reads tool annotations would warn a 2024-11-05
// server for leaving out something it has no way to send, and a check that
// validates structuredContent would pass one on an absence. Both are the
// report describing passmcp rather than the server. So each such check is
// skipped with the revision named, and handshake.protocol_version carries
// the judgement once, where it belongs.

// revisionFeature is a field or mechanism a later revision introduced.
// Each one here is taken from the specification's own changelog for the
// revision named in since.
type revisionFeature struct {
	since string
	what  string
}

var (
	// featAnnotations: 2025-03-26 "Added comprehensive tool annotations".
	featAnnotations = revisionFeature{transport.V20250326, "tool annotations (readOnlyHint, destructiveHint, idempotentHint)"}
	// featStructured: 2025-06-18 "Add support for structured tool output".
	featStructured = revisionFeature{transport.V20250618, "structured tool output (outputSchema and structuredContent)"}
)

// negotiatedVersion is the revision this run settled on: the stateless
// revision, the version initialize returned, or "" when neither is known.
func (s *Session) negotiatedVersion() string {
	switch {
	case s.Stateless():
		return s.Era.Version
	case s.Init != nil:
		return s.Init.ProtocolVersion
	}
	return ""
}

// lacks reports whether the negotiated revision predates f. Revisions are
// ISO dates, so they order as strings. An unknown version lacks nothing:
// with no handshake there is nothing to gate on.
func (s *Session) lacks(f revisionFeature) bool {
	v := s.negotiatedVersion()
	return v != "" && v < f.since
}

// lacksReason is the skip reason for a check about f.
func (s *Session) lacksReason(f revisionFeature) string {
	return fmt.Sprintf("%s arrived in the %s revision; this server negotiated %s, which has no such field, so there is nothing to grade",
		f.what, f.since, s.negotiatedVersion())
}

// protocolVersionFinding is the handshake.protocol_version verdict.
//
// The newest revision passes. 2025-06-18 and 2025-03-26 are information:
// both carry tool annotations and Streamable HTTP, so every check has its
// subject and a client loses little. 2024-11-05 is a warning, because what
// it lacks is what a cautious client acts on: with no annotations nothing
// separates a read-only tool from a destructive one, and its HTTP binding
// is a transport current clients are not required to speak. It is not a
// failure: the revision is negotiable, and the server works.
func protocolVersionFinding(c *check, v string) Finding {
	newest := passmcp.SupportedProtocolVersions[0]
	switch {
	case v == newest:
		return c.pass(v)
	case v < transport.V20250326:
		return c.warn(
			fmt.Sprintf("%s (passmcp offered %s), the first published revision. It predates the Streamable HTTP transport, "+
				"the OAuth 2.1 authorization framework and tool annotations (all 2025-03-26), and structured tool output "+
				"(outputSchema and structuredContent) and elicitation (both 2025-06-18). The checks that read those are skipped, "+
				"and with no readOnlyHint to go on no tool is invoked by default", v, newest),
			"move to a current revision; an SDK upgrade usually carries it. Until then no client can tell this server's "+
				"read-only tools from its destructive ones, and over HTTP its revision's transport is HTTP+SSE, which "+
				"current clients are not required to support")
	default:
		return c.info(fmt.Sprintf("%s (passmcp offered %s)", v, newest))
	}
}

// noToolsForLegacy is the execution.tools verdict when a revision without
// annotations left the read-only policy nothing to invoke.
//
// ADR-0004 invokes a tool only when it declares readOnlyHint: true, and a
// tool that declares nothing is destructive by the specification's default.
// On 2024-11-05 there is nothing to declare, so this is the expected
// outcome rather than a defect: the finding says why and which flag
// changes it, instead of telling the server to add a field its revision
// does not have.
func noToolsForLegacy(c *check, s *Session) Finding {
	return c.skip(fmt.Sprintf(
		"0 of %d tools executed: %s has no tool annotations, so every tool is destructive by the specification's default "+
			"and the read-only policy invokes none (ADR-0004). --allow-destructive invokes them; use it only where the "+
			"tools are known to be safe to call. --allow-mutations is not enough, because it adds only tools that declare "+
			"destructiveHint: false", len(s.Tools), s.negotiatedVersion()))
}

// sseProbeTimeout bounds the GET that asks whether an endpoint is on the
// HTTP+SSE transport. The old transport sends its endpoint event as soon as
// the stream opens, so a stream still silent after this is not it.
const sseProbeTimeout = 5 * time.Second

// sseEndpoint asks whether the endpoint speaks the 2024-11-05 HTTP+SSE
// transport, the way the specification tells a client to find out: after a
// POST was refused with a 4xx, a GET opens an event stream whose first
// event is endpoint, naming where messages are to be posted. It returns
// that URI. The GET goes over the bare transport, like the first contact it
// follows (ADR-0001).
func sseEndpoint(ctx context.Context, s *Session) (string, bool) {
	gctx, cancel := context.WithTimeout(telemetry.WithPhase(ctx, "discovery", "HTTP+SSE probe"), min(sseProbeTimeout, s.Opts.CallTimeout))
	defer cancel()
	req, err := http.NewRequestWithContext(gctx, http.MethodGet, s.Bare.Endpoint, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := s.Bare.Client.Do(req)
	if err != nil {
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != http.StatusOK || ct != "text/event-stream" {
		return "", false
	}
	return firstEndpointEvent(io.LimitReader(resp.Body, 64<<10))
}

// firstEndpointEvent reads the first event of a stream and returns its data
// when it is an endpoint event. Comment lines and blank lines before it are
// not events.
func firstEndpointEvent(r io.Reader) (string, bool) {
	sc := bufio.NewScanner(r)
	var event string
	var data []string
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "" && event == "" && len(data) == 0:
		case line == "":
			return strings.Join(data, "\n"), event == "endpoint"
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	return "", false
}

// legacySSEFinding is the discovery.first_contact verdict for a server on
// the HTTP+SSE transport, and blocks the run with the reason.
//
// The server is not broken: it speaks the transport of its revision. But
// that transport was replaced in 2025-03-26, passmcp does not implement it,
// and a current client is not required to either, so the finding is a
// critical one for anybody choosing this server for an agent, with the way
// to still run the diagnostic in the advice.
func legacySSEFinding(s *Session, c *check, status int, endpoint string) Finding {
	f := c.fail(Critical,
		fmt.Sprintf("the server speaks the 2024-11-05 HTTP+SSE transport: POST was refused with HTTP %d, and a GET opened an event stream whose first event is endpoint (%s). passmcp speaks Streamable HTTP, which replaced HTTP+SSE in 2025-03-26, and does not implement the old transport",
			status, truncate(endpoint, 120)),
		"serve Streamable HTTP at this URL; current SDKs provide it, and most can host the old endpoints alongside it for older clients. "+
			"If the server can also run as a program, passmcp can check it over stdio: passmcp check --stdio -- <command>")
	s.blocked = "the server speaks the 2024-11-05 HTTP+SSE transport, which passmcp does not implement"
	return f
}
