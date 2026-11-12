// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"fmt"
	"strings"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/telemetry"
)

// phaseHandshake runs initialize with credentials and inspects the result.
func phaseHandshake(ctx context.Context, s *Session) []Finding {
	var out []Finding
	// Which generation the server speaks was decided in the discovery phase,
	// because on the current revision there is no handshake to decide it.
	out = append(out, checkEra(ctx, s))
	if s.Stateless() {
		out = append(out, s.setupStateless(ctx)...)
		return out
	}
	c := s.check("handshake.initialize", "initialize succeeds")
	res, err := s.Client.Initialize(telemetry.WithPhase(ctx, "handshake", "initialize"))
	if err != nil {
		return append(out, initializeFailed(s, c, err))
	}
	s.Init = res
	s.Reached = true
	out = append(out, c.pass(fmt.Sprintf("%s %s", res.ServerInfo.Name, res.ServerInfo.Version)))

	out = append(out, protocolVersionFinding(s.check("handshake.protocol_version", "Negotiated protocol version"), res.ProtocolVersion))

	c = s.check("handshake.server_info", "serverInfo populated")
	switch {
	case res.ServerInfo.Name == "":
		out = append(out, c.fail(Minor, "serverInfo.name is empty", "set name and version"))
	case res.ServerInfo.Version == "":
		out = append(out, c.warn("serverInfo.version is empty", "set version so clients can report it"))
	default:
		out = append(out, c.pass(res.ServerInfo.Name+" "+res.ServerInfo.Version))
	}

	out = append(out, capabilitiesFinding(s.check("handshake.capabilities", "Capabilities advertised"), res.Capabilities))

	c = s.check("handshake.instructions", "Server instructions")
	if res.Instructions == "" {
		out = append(out, c.info("none provided"))
	} else {
		out = append(out, c.pass(fmt.Sprintf("%d characters", len(res.Instructions))))
	}

	return append(out, sessionIssuedFinding(s))
}

// initializeFailed is the handshake.initialize verdict when initialize did
// not return a result, and blocks every later phase with the reason.
func initializeFailed(s *Session, c *check, err error) Finding {
	if ch, ok := passmcp.Unauthorized(err); ok {
		detail := unauthorizedDetail(ch.Params)
		advice := "the token is not accepted here: check it has not expired, that --resource matches the audience the server expects, that --scope covers what it requires, and that any tenant parameter is passed with --param"
		if s.Opts.Creds.Effective() == creds.ModeBearer {
			advice = "the supplied token is not accepted here: confirm it was issued for this endpoint (audience/resource), has not expired, and carries the scope the server requires; if the operator gave you a client id and secret instead, use --auth client-credentials"
		}
		f := c.fail(Critical, detail, advice)
		s.blocked = "credentials rejected at initialize"
		return f
	}
	f := c.fail(Critical, err.Error(), "initialize must return a result")
	s.blocked = "initialize failed"
	return f
}

// unauthorizedDetail says what a 401 at initialize carried in its
// WWW-Authenticate challenge.
func unauthorizedDetail(params map[string]string) string {
	detail := "the server answered 401 to a request carrying the token"
	e := params["error"]
	if e == "" {
		return detail + " and gave no error code in WWW-Authenticate"
	}
	detail += " (" + e
	if d := params["error_description"]; d != "" {
		detail += ": " + d
	}
	return detail + ")"
}

// capabilitiesFinding is the handshake.capabilities verdict: which of the
// listable capabilities the server declared.
func capabilitiesFinding(c *check, capabilities passmcp.ServerCapabilities) Finding {
	var caps []string
	if capabilities.Tools != nil {
		caps = append(caps, "tools")
	}
	if capabilities.Resources != nil {
		caps = append(caps, "resources")
	}
	if capabilities.Prompts != nil {
		caps = append(caps, "prompts")
	}
	if capabilities.Logging != nil {
		caps = append(caps, "logging")
	}
	if len(caps) == 0 {
		return c.warn("no capabilities declared", "declare tools/resources/prompts so clients know what to list")
	}
	return c.pass(strings.Join(caps, ", "))
}

// sessionIssuedFinding is the handshake.session verdict: whether the server
// issued an Mcp-Session-Id.
func sessionIssuedFinding(s *Session) Finding {
	c := s.check("handshake.session", "Mcp-Session-Id issued")
	switch {
	case s.overStdio():
		// Not an absence to report as a finding about the server: the
		// connection is the session over a pipe, so there is no id for a
		// correct server to issue.
		return c.skip("sessions are an HTTP binding; over stdio the connection is the session")
	case s.Client.Conn().SessionID() != "":
		s.SessionID = true
		return c.pass("session id present")
	default:
		return c.info("stateless server (no session id)")
	}
}
