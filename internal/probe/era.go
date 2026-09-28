// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/telemetry"
	"satellion.com/passmcp/transport"
)

// checkEra reports which generation of the protocol the server speaks.
//
// The 2026-07-28 revision removed the initialize handshake and the session
// header and moved every request's metadata into _meta. A server still on
// the handshake revisions is not broken — the older versions remain
// implementable — but an operator choosing a server for an agent needs to
// know how far behind it is, and a server author needs to know the clock is
// running. Neither shows up anywhere else in the report.
//
// The probe is a single stateless request, sent before the handshake and
// undone afterwards, so nothing downstream sees a changed binding.
func checkEra(ctx context.Context, s *Session) Finding {
	c := s.check("handshake.protocol_era", "Protocol generation")
	if s.Opts.SkipEraCheck {
		return c.skip("--skip-era-check was passed, so the probe that identifies the protocol generation was not sent")
	}

	// The discovery phase already settled this, on the credential-free
	// transport, because first contact had to know which request to send.
	// Asking again would be a second request against a server passmcp is only
	// meant to observe.
	if s.Era == nil {
		s.settleEra(ctx)
	}
	var disc *passmcp.DiscoverResult
	stateless := s.Stateless()
	if s.Era != nil {
		disc = s.Era.Discovered
	}
	if stateless {
		detail := "speaks " + passmcp.StatelessVersions[0] + ", the current stateless revision"
		if disc != nil && disc.ServerInfo.Name != "" {
			detail += " (" + disc.ServerInfo.Name + " " + disc.ServerInfo.Version + ")"
		}
		return c.pass(detail)
	}

	// Not stateless. The version is whatever the handshake that follows
	// negotiates, and the era was already recorded.
	return c.warn(
		"speaks a handshake revision: it uses initialize and "+transport.HeaderSessionID+", which "+passmcp.StatelessVersions[0]+" removed",
		"the current revision is "+passmcp.StatelessVersions[0]+
			": requests carry their own protocol version, client identity and capabilities in _meta, sessions are gone, and "+
			transport.HeaderMethod+"/"+transport.HeaderName+" let a gateway route without parsing the body. "+
			"Agents on current clients will keep working through the compatibility rules, but plan the move")
}

// statelessBareProbe asks, without credentials, whether the endpoint
// answers a stateless request. It goes over the bare transport so first
// contact stays unauthenticated, as ADR-0001 requires.
func statelessBareProbe(ctx context.Context, s *Session) (*passmcp.DiscoverResult, bool) {
	return statelessProbe(ctx, s, s.Bare, "discovery")
}

// statelessProbe sends one server/discover on tr under the stateless
// dialect and reports whether the endpoint answered it, restoring the
// dialect afterwards.
//
// A server on the current revision either answers, or refuses with the
// shape the revision defines for an unimplemented RPC: HTTP 404 carrying a
// JSON-RPC -32601. A handshake-era server answers -32601 too — it does not
// know the method either — but at HTTP 200, so the status is the whole
// signal. Reading a bare -32601 as proof would label every legacy server as
// current, which is the one thing this check exists to avoid.
func statelessProbe(ctx context.Context, s *Session, tr *transport.Streamable, phase string) (*passmcp.DiscoverResult, bool) {
	restore := tr.Dialect()
	defer func() {
		tr.SetDialect(restore)
		tr.Reset()
	}()

	caps, err := json.Marshal(struct{}{})
	if err != nil {
		return nil, false
	}
	tr.SetDialect(&transport.Stateless{
		ProtocolVersion: passmcp.StatelessVersions[0],
		ClientInfo:      transport.Implementation{Name: "passmcp", Version: s.Opts.Version},
		Capabilities:    caps,
	})

	var out passmcp.DiscoverResult
	cctx := telemetry.WithPhase(ctx, phase, "stateless probe")
	err = tr.Call(cctx, "server/discover", map[string]any{}, &out)
	switch {
	case err == nil:
		return &out, true
	case isStatelessMethodNotFound(err):
		// It took the request; it just does not implement the optional RPC.
		return nil, true
	}
	return nil, false
}

// isStatelessMethodNotFound is the current revision's shape for an
// unimplemented RPC: HTTP 404 carrying a JSON-RPC -32601. A handshake-era
// server answers -32601 too, but at HTTP 200.
func isStatelessMethodNotFound(err error) bool {
	var he *transport.HTTPStatusError
	return errors.As(err, &he) &&
		he.StatusCode == http.StatusNotFound &&
		he.RPCError != nil &&
		he.RPCError.Code == transport.CodeMethodNotFound
}

// settleEra decides which generation the server speaks, before anything
// depends on the answer. It is credential-free and costs one request.
//
// Under the handshake revisions the era was implicit: initialize either
// worked or it did not. The stateless revision removed initialize, so a
// diagnostic that opens with one learns nothing from a server that speaks
// it — the refusal is about the missing method, not about authorization.
func (s *Session) settleEra(ctx context.Context) {
	if s.Era != nil || s.Opts.SkipEraCheck {
		return
	}
	if disc, ok := statelessProbe(ctx, s, s.Bare, "discovery"); ok {
		s.Era = &passmcp.Negotiation{
			Era: passmcp.EraStateless, Version: passmcp.StatelessVersions[0], Discovered: disc,
			Reason: "it answered a stateless request",
		}
		return
	}
	s.Era = &passmcp.Negotiation{Era: passmcp.EraSession, Reason: "it did not answer a stateless request"}
}

// Stateless reports whether the server speaks the stateless revision.
func (s *Session) Stateless() bool {
	return s.Era != nil && s.Era.Era == passmcp.EraStateless
}

// firstContact makes the opening unauthenticated request in whichever
// shape the server's generation calls for.
func (s *Session) firstContact(ctx context.Context) (*transport.RawResult, error) {
	tr := s.Bare
	cctx := telemetry.WithPhase(ctx, "discovery", "unauthenticated first contact")
	id := tr.NextID()

	if !s.Stateless() {
		return tr.Do(cctx, transport.RawOptions{
			Request:     &transport.Request{JSONRPC: "2.0", ID: &id, Method: "initialize", Params: initParams(s)},
			OmitSession: true,
		})
	}

	// On the stateless revision, tools/list is the cheapest request that
	// every server implements and that authorization applies to.
	caps, err := json.Marshal(struct{}{})
	if err != nil {
		return nil, err
	}
	d := &transport.Stateless{
		ProtocolVersion: passmcp.StatelessVersions[0],
		ClientInfo:      transport.Implementation{Name: "passmcp", Version: s.Opts.Version},
		Capabilities:    caps,
	}
	rpc := &transport.Request{JSONRPC: "2.0", ID: &id, Method: "tools/list", Params: json.RawMessage(`{}`)}
	if err := d.PrepareBody(rpc); err != nil {
		return nil, err
	}
	hdr := http.Header{}
	if err := d.PrepareHeaders(hdr, rpc); err != nil {
		return nil, err
	}
	headers := map[string]string{transport.HeaderSessionID: ""} // never send one
	for k := range hdr {
		headers[k] = hdr.Get(k)
	}
	return tr.Do(cctx, transport.RawOptions{Request: rpc, Headers: headers, OmitSession: true, OmitProtocolVersion: true})
}

// setupStateless prepares the session for a server on the stateless
// revision, in place of the handshake the revision removed.
//
// There is no initialize to report on, so what replaces those findings is
// what the revision put in its stead: whether server/discover answers, and
// whether the routing headers a gateway depends on are honoured.
func (s *Session) setupStateless(ctx context.Context) []Finding {
	var out []Finding

	caps, err := json.Marshal(struct{}{})
	if err != nil {
		return append(out, s.check("handshake.stateless", "Stateless session setup").fail(Major, err.Error(), ""))
	}
	// Conn, not Transport: the dialect belongs to whichever connection this
	// is, and over a pipe Transport is nil.
	s.Client.Conn().SetDialect(&transport.Stateless{
		ProtocolVersion: passmcp.StatelessVersions[0],
		ClientInfo:      transport.Implementation{Name: "passmcp", Version: s.Opts.Version},
		Capabilities:    caps,
	})

	c := s.check("handshake.server_info", "Server identifies itself")
	d := s.Era.Discovered
	switch {
	case d == nil:
		// The specification is explicit that every server MUST implement
		// server/discover: it is the only way a client on this revision
		// learns a server's identity, capabilities and supported versions.
		s.Init = &passmcp.InitializeResult{ProtocolVersion: passmcp.StatelessVersions[0]}
		out = append(out, c.fail(Major, "the server does not implement server/discover",
			"implement server/discover. "+passmcp.StatelessVersions[0]+" requires it: with initialize gone it is the only way a client learns your identity, capabilities and which protocol versions you support"))
	case d.ServerInfo.Name == "":
		// It answered, so its capabilities and instructions are real and
		// the catalog must be judged against them. Only the identity is
		// missing, and that is a smaller defect than the RPC itself.
		s.Init = &passmcp.InitializeResult{
			ProtocolVersion: passmcp.StatelessVersions[0],
			Capabilities:    d.Capabilities,
			Instructions:    d.Instructions,
		}
		out = append(out, c.fail(Minor, "server/discover answered without a server identity",
			"put name and version in the result's _meta under "+transport.MetaServerInfo+"; that is where "+passmcp.StatelessVersions[0]+" carries serverInfo, and without it a client cannot say which server it reached"))
	case d.ServerInfo.Version == "":
		s.Init = &passmcp.InitializeResult{
			ProtocolVersion: passmcp.StatelessVersions[0],
			ServerInfo:      d.ServerInfo,
			Capabilities:    d.Capabilities,
			Instructions:    d.Instructions,
		}
		out = append(out, c.warn(d.ServerInfo.Name+" via server/discover, but serverInfo.version is empty", "set version so clients can report it"))
	default:
		s.Init = &passmcp.InitializeResult{
			ProtocolVersion: passmcp.StatelessVersions[0],
			ServerInfo:      d.ServerInfo,
			Capabilities:    d.Capabilities,
			Instructions:    d.Instructions,
		}
		out = append(out, c.pass(fmt.Sprintf("%s %s via server/discover", d.ServerInfo.Name, d.ServerInfo.Version)))
	}

	out = append(out, s.checkRoutingHeaders(ctx))
	return out
}

// checkRoutingHeaders verifies the server honours the headers the stateless
// revision requires a client to mirror its body into.
//
// The point of those headers is that a gateway, rate limiter or WAF can
// route and meter on them without parsing JSON. That only holds if the
// server rejects a request whose headers disagree with its body — otherwise
// the two components are acting on different truths, which is exactly the
// confusion the mirroring was meant to remove.
func (s *Session) checkRoutingHeaders(ctx context.Context) Finding {
	c := s.check("protocol.routing_headers", "Mirrored routing headers are validated")
	// The mirrored headers are an HTTP binding; there is nothing to mirror
	// on a pipe.
	tr, overHTTP := s.Client.HTTP()
	if !overHTTP {
		return c.skip("the routing headers are an HTTP binding")
	}
	id := tr.NextID()

	rpc := &transport.Request{JSONRPC: "2.0", ID: &id, Method: "tools/list", Params: json.RawMessage(`{}`)}
	if err := tr.Dialect().PrepareBody(rpc); err != nil {
		return c.skip("could not build the probe: " + err.Error())
	}
	// Deliberately disagree with the body.
	raw, err := tr.Do(telemetry.WithPhase(ctx, "protocol", "header mismatch"), transport.RawOptions{
		Request: rpc,
		Headers: map[string]string{
			transport.HeaderMethod:          "tools/call",
			transport.HeaderProtocolVersion: passmcp.StatelessVersions[0],
		},
		OmitSession:         true,
		OmitProtocolVersion: true,
	})
	if err != nil {
		return c.skip("the probe did not complete: " + err.Error())
	}
	switch {
	case raw.Status == http.StatusBadRequest && raw.Response != nil && raw.Response.Error != nil &&
		raw.Response.Error.Code == transport.CodeHeaderMismatch:
		return c.pass("a header disagreeing with the body is refused with -32020")
	case raw.Status >= 400:
		return c.warn(fmt.Sprintf("refused with HTTP %d, but not the -32020 the revision defines", raw.Status),
			"answer 400 with JSON-RPC error -32020 (HeaderMismatch) so a client can tell this apart from an ordinary rejection")
	default:
		return c.fail(Major, fmt.Sprintf("accepted a request whose %s header said tools/call while the body said tools/list (HTTP %d)", transport.HeaderMethod, raw.Status),
			"validate the mirrored headers against the body and refuse a mismatch with -32020: a gateway routing on the header and a server executing the body would otherwise act on different requests")
	}
}

// checkStatelessness verifies the server treats each request independently.
//
// This is the whole point of the revision: if any request depends on a
// previous one having been seen on the same connection, the server cannot
// sit behind a round-robin load balancer, and the operator will discover
// that under load rather than here. The probe interleaves the same call
// across two independent connections; a server that is genuinely stateless
// cannot tell the difference.
func (s *Session) checkStatelessness(ctx context.Context) Finding {
	c := s.check("resilience.stateless", "Requests do not depend on the connection")
	if len(s.Tools) == 0 {
		return c.skip("no tool to exercise")
	}

	caps, err := json.Marshal(struct{}{})
	if err != nil {
		return c.skip(err.Error())
	}
	dialect := func() *transport.Stateless {
		return &transport.Stateless{
			ProtocolVersion: passmcp.StatelessVersions[0],
			ClientInfo:      transport.Implementation{Name: "passmcp", Version: s.Opts.Version},
			Capabilities:    caps,
		}
	}

	// Two transports means two connection pools, so the second request
	// cannot inherit anything the first established.
	base := &http.Client{Transport: s.Transport, Timeout: s.Opts.CallTimeout}
	first := transport.New(s.Opts.Endpoint, base)
	first.SetDialect(dialect())
	second := transport.New(s.Opts.Endpoint, &http.Client{Transport: s.Transport, Timeout: s.Opts.CallTimeout})
	second.SetDialect(dialect())

	cctx := telemetry.WithPhase(ctx, "resilience", "statelessness")
	var a, b listToolsShape
	if err := first.Call(cctx, "tools/list", map[string]any{}, &a); err != nil {
		return c.skip("the first request did not complete: " + err.Error())
	}
	if err := second.Call(cctx, "tools/list", map[string]any{}, &b); err != nil {
		return c.fail(Major,
			"the same request succeeded on one connection and failed on another: "+err.Error(),
			"every request must carry what the server needs; nothing may be inferred from a previous request on the same connection, or a load balancer will break this server")
	}
	if len(a.Tools) != len(b.Tools) {
		return c.fail(Major,
			fmt.Sprintf("the same request returned %d tools on one connection and %d on another", len(a.Tools), len(b.Tools)),
			"a request's answer must not depend on which connection carried it")
	}
	// Same count is not same answer. The 2026-07-28 revision makes lists
	// cacheable and connection-independent, so a client may serve either
	// answer from cache: two catalogues that differ in content, even at
	// the same size, mean a cached list is wrong for somebody.
	if diff := a.differsFrom(b); diff != "" {
		return c.fail(Major,
			"the same request returned different tools on two independent connections: "+diff,
			"a list must be the same whichever connection asks for it; the revision makes lists cacheable, so a client may serve one connection's answer to another")
	}
	return c.pass(fmt.Sprintf("the same request gave the same answer on two independent connections (%d tools, identical definitions)", len(a.Tools)))
}

// listToolsShape is the little of tools/list this check needs: each tool's
// name, and its whole definition kept raw so two answers can be compared
// without passmcp deciding which fields matter.
type listToolsShape struct {
	Tools []json.RawMessage `json:"tools"`
}

// differsFrom says how two tools/list answers differ, by tool name, or ""
// when every definition is the same. Definitions are compared after
// decoding, so key order and whitespace — which the wire does not fix —
// are not differences.
func (a listToolsShape) differsFrom(b listToolsShape) string {
	index := func(l listToolsShape) map[string]any {
		out := map[string]any{}
		for i, raw := range l.Tools {
			var def map[string]any
			if json.Unmarshal(raw, &def) != nil {
				out[fmt.Sprintf("#%d (unreadable)", i)] = string(raw)
				continue
			}
			name, _ := def["name"].(string)
			out[name] = def
		}
		return out
	}
	x, y := index(a), index(b)
	var names []string
	for n := range x {
		names = append(names, n)
	}
	for n := range y {
		if _, ok := x[n]; !ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	var only1, only2, changed []string
	for _, n := range names {
		dx, inX := x[n]
		dy, inY := y[n]
		switch {
		case !inY:
			only1 = append(only1, n)
		case !inX:
			only2 = append(only2, n)
		case !reflect.DeepEqual(dx, dy):
			changed = append(changed, n)
		}
	}
	var parts []string
	if len(only1) > 0 {
		parts = append(parts, "only on the first: "+list(only1))
	}
	if len(only2) > 0 {
		parts = append(parts, "only on the second: "+list(only2))
	}
	if len(changed) > 0 {
		parts = append(parts, "defined differently: "+list(changed))
	}
	return strings.Join(parts, "; ")
}

// liveness is the cheapest request that proves a server is answering.
//
// It differs by revision because 2026-07-28 removed ping outright: a
// stateless server answering -32601 to a ping is behaving correctly, and
// passmcp reporting that as a failure would be the worst kind of diagnostic
// bug — one that tells a conformant author to break their server. On that
// revision the equivalent is server/discover, which the specification
// requires every server to implement.
func (s *Session) liveness() (method string, params any) {
	if s.Stateless() {
		return "server/discover", map[string]any{}
	}
	return "ping", nil
}

// livenessName is what the report calls the liveness probe.
func (s *Session) livenessName() string {
	m, _ := s.liveness()
	return m
}
