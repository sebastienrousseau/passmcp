// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/telemetry"
	"satellion.com/passmcp/transport"
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

// phaseProtocol sends deliberately unusual requests and checks the server
// answers them the way the JSON-RPC and MCP specifications require.
func phaseProtocol(ctx context.Context, s *Session) []Finding {
	var out []Finding
	pctx := func(label string) context.Context { return telemetry.WithPhase(ctx, "protocol", label) }

	// What the server added, before anything about what it answers: an
	// advertised extension is interface, and the checks below only exercise
	// the base protocol.
	out = append(out, checkExtensions(s))

	live, liveParams := s.liveness()
	out = append(out, protocolPing(s, pctx, live, liveParams))

	// The four probes below send something a client library would refuse to
	// build: an unknown method, a request whose id must come back, a
	// truncated body, a call with its required parameter missing. None of
	// them is about HTTP, so all four run over a pipe too — which is why
	// they go through rawExchange rather than straight to the HTTP
	// transport. The ones that genuinely are about HTTP come after, and say
	// so when they cannot run.
	// One deadline per probe, not one for the block. A server that ignores
	// a message it could not parse answers with silence, and silence has to
	// be bounded — but sharing one budget across four probes would make the
	// first slow answer eat the other three, and they would report the
	// server as unresponsive when it was the clock.
	raw := func(label string, send rawSend) (rawReply, error) {
		rctx, cancel := s.stdioDeadline(telemetry.WithPhase(ctx, "protocol", label))
		defer cancel()
		return s.rawExchange(rctx, send)
	}

	out = append(out, probeUnknownMethod(s, raw))
	out = append(out, probeIDEcho(s, raw, live, liveParams))
	out = append(out, probeMalformedJSON(s, raw))
	out = append(out, probeInvalidParams(s, raw))
	out = append(out, probeUnknownTool(s, pctx))

	// And what it has not removed. Transport-agnostic like the four above,
	// so it runs over a pipe too.
	out = append(out, checkDeprecatedFeatures(ctx, s))

	// From here on the probes are about the HTTP binding rather than about
	// MCP. Over a pipe they are named and skipped: a report that simply
	// contained fewer checks would read as a better result.
	tr, overHTTP := s.Client.HTTP()
	if !overHTTP {
		return append(out, s.skipHTTPOnly()...)
	}

	out = append(out, probeAcceptHeader(s, tr, pctx, live, liveParams))
	out = append(out, probeGetStream(s, tr, pctx))
	if s.SessionID {
		out = append(out, probeBogusSession(s, tr, pctx, live, liveParams))
	}
	out = append(out, probeVersionHeader(s, tr, pctx, live, liveParams))

	out = append(out, checkOrigin(pctx("foreign origin"), s, tr, live, liveParams))
	return append(out, checkReplies(s, tr, pctx, live, liveParams)...)
}

// rawProbe sends one hand-built message through rawExchange under its own
// deadline.
type rawProbe func(label string, send rawSend) (rawReply, error)

// protocolPing is the protocol.ping verdict: the liveness call answers
// without asking the client for anything.
func protocolPing(s *Session, pctx func(string) context.Context, live string, liveParams any) Finding {
	c := s.check("protocol.ping", live)
	err := s.Client.Call(pctx(live), live, liveParams, nil)
	ir, needsInput := asInputRequired(err)
	switch {
	case err == nil:
		return c.pass("ok")
	case needsInput:
		// Still a failure, and worth saying why in its own words: a liveness
		// call is the one request that cannot have a conversation attached
		// to it, because its whole purpose is to be answerable with no state
		// and no user present.
		s.MRTR = append(s.MRTR, observe(live, ir))
		return c.fail(Major,
			fmt.Sprintf("%s answered input_required, asking for %s", live, list(requestedMethods(ir))),
			"answer "+live+" without requiring anything from the client. It is what a client calls to find out whether the server is alive, so a version of it that needs a user present cannot be used for that — every liveness probe becomes a conversation nobody is there to have")
	default:
		return c.fail(Major, err.Error(), "implement ping; clients use it for liveness")
	}
}

// probeUnknownMethod is the protocol.unknown_method verdict: an unknown
// method draws -32601.
func probeUnknownMethod(s *Session, raw rawProbe) Finding {
	c := s.check("protocol.unknown_method", "Unknown method returns -32601")
	id := s.nextID()
	rep, err := raw("unknown method", rawSend{Request: &transport.Request{JSONRPC: "2.0", ID: &id, Method: "passmcp/does_not_exist"}})
	switch {
	case err != nil:
		return c.warn("request failed: "+err.Error(), "")
	case rep.Response != nil && rep.Response.Error != nil && rep.Response.Error.Code == -32601:
		return c.pass("-32601 Method not found")
	case rep.Response != nil && rep.Response.Error != nil:
		return c.warn(fmt.Sprintf("error code %d (%s); -32601 expected", rep.Response.Error.Code, rep.Response.Error.Message), "use -32601 for unknown methods")
	case rep.HTTP && rep.Status >= 400:
		return c.warn(fmt.Sprintf("HTTP %d instead of a JSON-RPC error", rep.Status), "answer 200 with a JSON-RPC error object")
	default:
		return c.fail(Minor, "no error returned for an unknown method", "return -32601")
	}
}

// probeIDEcho is the protocol.id_echo verdict: the response carries the
// request's id and jsonrpc 2.0.
func probeIDEcho(s *Session, raw rawProbe, live string, liveParams any) Finding {
	c := s.check("protocol.id_echo", "Response id matches request id")
	id := s.nextID()
	// AnyMessage, because the whole question is whether the id comes back
	// right. Matching the reply by id — which is how every other call on a
	// pipe finds its answer — would drop a mismatched one and report that
	// the server never answered.
	rep, err := raw("id echo", rawSend{
		Request:    &transport.Request{JSONRPC: "2.0", ID: &id, Method: live, Params: liveJSON(liveParams)},
		AnyMessage: true,
	})
	switch {
	case err != nil:
		return c.warn("request failed: "+err.Error(), "")
	case rep.Response == nil:
		return c.fail(Major, fmt.Sprintf("the answer is not a JSON-RPC response: %s", truncate(string(rep.Body), 120)), "")
	case rep.Response.ID == nil:
		return c.fail(Major, fmt.Sprintf("sent id %d, got no id", id), "echo the request id")
	case *rep.Response.ID != id:
		return c.fail(Major, fmt.Sprintf("sent id %d, got %d", id, *rep.Response.ID), "echo the request id")
	case rep.Response.JSONRPC != "2.0":
		return c.warn(`jsonrpc field is not "2.0"`, "set jsonrpc: \"2.0\"")
	default:
		return c.pass("id echoed, jsonrpc 2.0")
	}
}

// probeMalformedJSON is the protocol.malformed_json verdict: a truncated
// body is rejected as a parse error.
func probeMalformedJSON(s *Session, raw rawProbe) Finding {
	c := s.check("protocol.malformed_json", "Malformed JSON is rejected")
	rep, err := raw("malformed json", rawSend{Body: []byte(`{"jsonrpc":"2.0","id":1,"method":`)})
	switch {
	case err != nil:
		// Over a pipe, silence is the common answer and it is a finding:
		// JSON-RPC requires a parse error to be reported, and a host whose
		// call never returns cannot tell a slow server from a lost one.
		if s.overStdio() {
			return c.fail(Minor, "no answer to a truncated message: "+err.Error(),
				"answer a body that does not parse with -32700 and a null id, rather than ignoring it")
		}
		return c.warn("request failed: "+err.Error(), "")
	case rep.HTTP && rep.Status == http.StatusBadRequest:
		return c.pass("HTTP 400")
	case rep.Response != nil && rep.Response.Error != nil && rep.Response.Error.Code == -32700:
		return c.pass("-32700 Parse error")
	case rep.Response != nil && rep.Response.Error != nil:
		return c.warn(fmt.Sprintf("error %d rather than -32700", rep.Response.Error.Code), "use -32700 for a body that does not parse")
	case rep.HTTP && rep.Status/100 == 2:
		return c.fail(Minor, fmt.Sprintf("HTTP %d for a truncated body", rep.Status), "return 400 or -32700")
	case rep.HTTP:
		return c.info(fmt.Sprintf("HTTP %d", rep.Status))
	default:
		return c.fail(Minor, "a truncated message drew a reply that was not an error: "+truncate(string(rep.Body), 120), "return -32700")
	}
}

// probeInvalidParams is the protocol.invalid_params verdict: a tools/call
// with no name is rejected.
func probeInvalidParams(s *Session, raw rawProbe) Finding {
	c := s.check("protocol.invalid_params", "tools/call without a name is rejected")
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

// probeAcceptHeader is the protocol.accept_header observation: how the
// server treats a request with no Accept header.
func probeAcceptHeader(s *Session, tr *transport.Streamable, pctx func(string) context.Context, live string, liveParams any) Finding {
	c := s.check("protocol.accept_header", "Request without Accept header")
	id := tr.NextID()
	hrep, err := tr.Do(pctx("no accept"), transport.RawOptions{Request: &transport.Request{JSONRPC: "2.0", ID: &id, Method: live, Params: liveJSON(liveParams)}, Headers: map[string]string{"Accept": ""}})
	switch {
	case err != nil:
		return c.info("request failed: " + err.Error())
	case hrep.Status == http.StatusNotAcceptable:
		return c.info("406: server insists on Accept (spec-strict)")
	case hrep.Status/100 == 2:
		return c.info("accepted without Accept header (lenient)")
	default:
		return c.info(fmt.Sprintf("HTTP %d", hrep.Status))
	}
}

// probeGetStream is the protocol.get_stream verdict.
//
// What a GET should do depends on the generation. The handshake
// revisions let a client open a standalone stream that way; the
// stateless revision removed it, and a server that still serves one is
// carrying a mechanism no current client will use.
func probeGetStream(s *Session, tr *transport.Streamable, pctx func(string) context.Context) Finding {
	c := s.check("protocol.get_stream", "GET on the MCP endpoint")
	hrep, err := tr.Do(pctx("GET stream"), transport.RawOptions{HTTPMethod: http.MethodGet, Headers: map[string]string{"Accept": "text/event-stream"}, SkipDialect: true, HeadersOnly: true})
	switch {
	case err != nil:
		return c.info("GET failed: " + truncate(err.Error(), 100))
	case s.Stateless() && hrep.Status == http.StatusMethodNotAllowed:
		return c.pass("405, as this revision requires")
	case s.Stateless() && hrep.Status/100 == 2 && hrep.ContentType == "text/event-stream":
		return c.warn("a GET still opens an event stream, which "+passmcp.StatelessVersions[0]+" removed",
			"answer 405 to GET: server-initiated streams were replaced by subscriptions/listen, and a client on this revision will never open one this way")
	case s.Stateless():
		return c.info(fmt.Sprintf("HTTP %d %s (this revision expects 405)", hrep.Status, hrep.ContentType))
	case hrep.Status == http.StatusMethodNotAllowed:
		return c.info("405: no server-initiated stream (allowed by spec)")
	case hrep.Status/100 == 2 && hrep.ContentType == "text/event-stream":
		return c.pass("text/event-stream")
	default:
		return c.info(fmt.Sprintf("HTTP %d %s", hrep.Status, hrep.ContentType))
	}
}

// probeBogusSession is the protocol.bogus_session verdict: a session id the
// server never issued is rejected.
func probeBogusSession(s *Session, tr *transport.Streamable, pctx func(string) context.Context, live string, liveParams any) Finding {
	c := s.check("protocol.bogus_session", "Unknown session id is rejected")
	id := tr.NextID()
	hrep, err := tr.Do(pctx("bogus session"), transport.RawOptions{Request: &transport.Request{JSONRPC: "2.0", ID: &id, Method: live, Params: liveJSON(liveParams)}, Headers: map[string]string{transport.HeaderSessionID: "passmcp-bogus-" + s.TraceID[:8]}})
	switch {
	case err != nil:
		return c.info("request failed: " + err.Error())
	case hrep.Status == http.StatusNotFound:
		return c.pass("404")
	case hrep.Status == http.StatusBadRequest:
		return c.pass("400")
	case hrep.Status/100 == 2:
		return c.warn("server answered a request carrying a session id it never issued", "reject unknown session ids with 404")
	default:
		return c.info(fmt.Sprintf("HTTP %d", hrep.Status))
	}
}

// probeVersionHeader is the protocol.version_header verdict: an unknown
// MCP-Protocol-Version is rejected.
func probeVersionHeader(s *Session, tr *transport.Streamable, pctx func(string) context.Context, live string, liveParams any) Finding {
	c := s.check("protocol.version_header", "Bad MCP-Protocol-Version is rejected")
	id := tr.NextID()
	hrep, err := tr.Do(pctx("bad version"), transport.RawOptions{Request: &transport.Request{JSONRPC: "2.0", ID: &id, Method: live, Params: liveJSON(liveParams)}, Headers: map[string]string{transport.HeaderProtocolVersion: "1999-01-01"}})
	switch {
	case err != nil:
		return c.info("request failed: " + err.Error())
	case hrep.Status == http.StatusBadRequest:
		return c.pass("400")
	case hrep.Status/100 == 2:
		return c.info("accepted (server does not validate the header)")
	default:
		return c.info(fmt.Sprintf("HTTP %d", hrep.Status))
	}
}

// foreignOrigin is what a page on an attacker's site would send. .invalid
// is reserved (RFC 6761) and can never resolve, so no server can
// legitimately list it.
const foreignOrigin = "https://passmcp-origin-probe.invalid"

// checkOrigin asks whether the server refuses a request from a web page
// it did not expect.
//
// The Streamable HTTP transport requires servers to validate Origin,
// because DNS rebinding lets any site a user visits point a hostname at
// 127.0.0.1 and drive a local server from the user's browser. The request
// carries the operator's credentials and a session, so the only thing
// wrong with it is where it claims to come from: a rejection can be
// attributed to the Origin and to nothing else.
func checkOrigin(ctx context.Context, s *Session, tr *transport.Streamable, live string, liveParams any) Finding {
	c := s.check("protocol.origin", "A foreign Origin is rejected")
	id := tr.NextID()
	hrep, err := tr.Do(ctx, transport.RawOptions{
		Request: &transport.Request{JSONRPC: "2.0", ID: &id, Method: live, Params: liveJSON(liveParams)},
		Headers: map[string]string{"Origin": foreignOrigin},
	})
	switch {
	case err != nil:
		return c.info("request failed: " + truncate(err.Error(), 100))
	case hrep.Status == http.StatusForbidden:
		return c.pass("403 for Origin " + foreignOrigin)
	case hrep.Status/100 == 4:
		// Refused, which is the property. The status is not the one the
		// specification names, and a client cannot tell this refusal from
		// any other 4xx, so it is said.
		return c.pass(fmt.Sprintf("HTTP %d for Origin %s (the specification asks for 403)", hrep.Status, foreignOrigin))
	case hrep.Status/100 != 2:
		return c.info(fmt.Sprintf("HTTP %d; neither served nor refused", hrep.Status))
	}
	advice := "reject requests whose Origin is not one you expect with 403; the Streamable HTTP transport requires it"
	if where, local := endpointLocality(ctx, s.URL.Hostname()); local {
		return c.fail(Major,
			fmt.Sprintf("served a request from Origin %s on %s: any web page the user opens can drive this server through DNS rebinding", foreignOrigin, where),
			advice+", and a server on this machine or network is exactly what DNS rebinding reaches")
	}
	return c.warn(
		fmt.Sprintf("served a request from Origin %s; the transport requires Origin validation, though a public endpoint is not what DNS rebinding reaches", foreignOrigin),
		advice)
}

// endpointLocality is localEndpoint, as a variable so a test can put a
// loopback fake on a public address.
var endpointLocality = localEndpoint

// localEndpoint reports whether a host is this machine or a private
// network, which is what DNS rebinding reaches, and says which.
func localEndpoint(ctx context.Context, host string) (string, bool) {
	if host == "localhost" {
		return "loopback", true
	}
	addrs := []string{host}
	if net.ParseIP(host) == nil {
		resolved, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil {
			return "", false
		}
		addrs = resolved
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		switch {
		case ip == nil:
		case ip.IsLoopback():
			return "loopback", true
		case ip.IsPrivate(), ip.IsLinkLocalUnicast():
			return "a private address", true
		}
	}
	return "", false
}

// phaseResilience checks recovery paths: session expiry and token refresh.
// liveJSON marshals liveness params, which are either nil or an empty
// object depending on the revision.
func liveJSON(v any) json.RawMessage {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

func phaseResilience(ctx context.Context, s *Session) []Finding {
	var out []Finding
	tr := s.Client.Transport()
	if s.Stateless() {
		// There is no session to lose. What matters instead is whether the
		// server really is stateless, because that is what lets a plain
		// round-robin load balancer sit in front of it.
		return append(out, s.checkStatelessness(ctx))
	}
	if s.SessionID {
		c := s.check("resilience.session_reinit", "Client recovers from a lost session")
		orig := tr.SessionID()
		tr.SetSessionID("passmcp-expired-" + s.TraceID[:8])
		err := s.Client.Ping(telemetry.WithPhase(ctx, "resilience", "expired session"))
		switch {
		case err == nil && tr.SessionID() != "" && tr.SessionID() != "passmcp-expired-"+s.TraceID[:8]:
			out = append(out, c.pass("404 observed, re-initialized, ping succeeded on a new session"))
		case err == nil:
			out = append(out, c.warn("server accepted the bogus session; recovery not exercised", "return 404 for unknown sessions so clients re-initialize"))
			tr.SetSessionID(orig)
		default:
			out = append(out, c.fail(Major, "recovery failed: "+err.Error(), ""))
			tr.SetSessionID(orig)
		}
	} else {
		out = append(out, s.check("resilience.session_reinit", "Session recovery").skip("stateless server"))
	}

	if s.Token != nil && s.RequiresAuth {
		out = append(out, checkTokenRefresh(ctx, s))
	}
	return out
}

// checkTokenRefresh is the resilience.token_refresh verdict: a call still
// succeeds after the cached token is invalidated.
func checkTokenRefresh(ctx context.Context, s *Session) Finding {
	c := s.check("resilience.token_refresh", "Token source can renew")
	src := s.Client.TokenSource()
	if src == nil {
		return c.skip("no token source")
	}
	src.Invalidate()
	if err := s.Client.Ping(telemetry.WithPhase(ctx, "resilience", "after invalidate")); err != nil {
		return c.fail(Major, "call after token invalidation failed: "+err.Error(), "check refresh_token / client-credentials re-issue")
	}
	return c.pass("call succeeded after invalidating the cached token")
}

func asRPC(err error, target **transport.RPCError) bool {
	for err != nil {
		var e *transport.RPCError
		if errors.As(err, &e) {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
