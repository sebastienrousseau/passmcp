// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/telemetry"
	"satellion.com/passmcp/transport"
)

// Two properties of the 2026-07-28 revision that passmcp modelled and never
// reported. Both are about the edges of the protocol rather than its centre,
// and both are things an operator cannot see from anywhere else.
//
// The first is what the server has added: server/discover carries a list of
// extensions, and every entry on it is surface an agent may exercise. A
// report that lists a server's tools and says nothing about the extensions
// beside them is describing half the interface.
//
// The second is what the server has not removed. The revision deleted
// initialize, ping and the session; a server that still answers the first
// two is either supporting older clients deliberately — which is allowed,
// and which supportedVersions is how it says so — or carrying handlers that
// no current client will ever call. Those two cases look identical from
// outside and mean opposite things, which is why this check reads
// supportedVersions before deciding which it is looking at.

// extensionID is a reverse-DNS identifier, optionally with a /name suffix:
// io.modelcontextprotocol/tasks, com.example.mcp/billing. The domain part
// must contain a dot, because that is the whole point of reverse-DNS — a
// bare word claims no namespace and collides with the next server that
// picks it.
var extensionID = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(/[A-Za-z0-9._-]+)*$`)

// specNamespace is the prefix the specification reserves for itself. It is
// how passmcp separates an extension defined by MCP from one an author
// invented, which is the difference between "this server speaks Tasks" and
// "this server speaks something only its own client knows about".
const specNamespace = "io.modelcontextprotocol"

// checkExtensions enumerates what the server advertises beyond the base
// protocol.
func checkExtensions(s *Session) Finding {
	c := s.check("protocol.extensions", "Advertised extensions")
	if !s.Stateless() {
		return c.skip("extensions are declared by server/discover, which the handshake revisions do not have")
	}
	if s.Era == nil || s.Era.Discovered == nil {
		// handshake.server_info already fails for this, with the advice.
		// Repeating it here would report one defect twice.
		return c.skip("the server does not implement server/discover, so it advertises nothing")
	}

	if s.Era.Discovered.ExtensionsMalformed {
		return c.warn("capabilities.extensions is present but is not an object, so no client can read which extensions the server supports",
			"make capabilities.extensions an object keyed by extension identifier, with a settings object as each value ({} for none)")
	}
	ids := s.Era.Discovered.ExtensionIDs()
	if len(ids) == 0 {
		if misplaced := s.Era.Discovered.Extensions; len(misplaced) > 0 {
			// Advertised, but in a field the specification does not define,
			// so a client reading capabilities.extensions — every client
			// that follows the specification — sees a server with none.
			return c.ev(misplaced...).warn(
				fmt.Sprintf("%s advertised in a top-level extensions list rather than in capabilities.extensions, where clients read them: %s",
					plural(len(misplaced), "extension"), list(misplaced)),
				"move them into capabilities.extensions, keyed by identifier with a settings object as the value ({} for none). As sent, a client following the specification sees a server with no extensions")
		}
		return c.info("none advertised: the server implements the base protocol only")
	}

	var malformed, spec, third []string
	for _, id := range ids {
		switch {
		case !extensionID.MatchString(id):
			malformed = append(malformed, id)
		case id == specNamespace || strings.HasPrefix(id, specNamespace+"/"):
			spec = append(spec, id)
		default:
			third = append(third, id)
		}
	}

	// The census wants this as evidence whatever the verdict, because the
	// interesting question across a population is which extensions exist at
	// all — and a server with one malformed identifier still tells us that.
	c = c.ev(ids...)

	if len(malformed) > 0 {
		sort.Strings(malformed)
		return c.warn(
			fmt.Sprintf("%s not a reverse-DNS identifier: %s", plural(len(malformed), "extension is"), list(malformed)),
			"name an extension after a domain you control — com.example.mcp/billing. An identifier with no domain in it claims no namespace, so the next server to pick the same word means something else by it and a client cannot tell the two apart")
	}

	detail := describeExtensions(spec, third)
	return c.pass(detail)
}

// describeExtensions says what was found, separating the specification's own
// extensions from an author's.
func describeExtensions(spec, third []string) string {
	sort.Strings(spec)
	sort.Strings(third)
	total := len(spec) + len(third)
	parts := make([]string, 0, 2)
	if len(spec) > 0 {
		parts = append(parts, fmt.Sprintf("%d defined by the specification (%s)", len(spec), list(spec)))
	}
	if len(third) > 0 {
		parts = append(parts, fmt.Sprintf("%d third-party (%s)", len(third), list(third)))
	}
	return fmt.Sprintf("%s advertised: %s", plural(total, "extension"), strings.Join(parts, ", "))
}

// removedMethod is a method the stateless revision deleted, with what it was
// for — the report has to name the mechanism, not just the method, or the
// finding reads as a spelling complaint.
type removedMethod struct {
	Method string
	Was    string
	Params json.RawMessage
}

// removedMethods are the two the revision removed that a server can still be
// asked about without changing anything. The session header and the GET
// event stream were removed too; protocol.get_stream covers the second, and
// the first cannot be probed by asking for it — a server either issues one
// or it does not, which handshake.session already reports.
var removedMethods = []removedMethod{
	{Method: "initialize", Was: "the opening handshake"},
	{Method: "ping", Was: "liveness"},
}

// checkDeprecatedFeatures asks whether the surface the revision removed is
// actually gone.
//
// Answering initialize and ping is not a conformance failure: the
// compatibility rules let one server serve both generations, and a great
// many will for years. What matters is whether the server says so.
// supportedVersions is how a client learns it can fall back, and a server
// that keeps the handlers without declaring the versions has the code
// without the contract — so a client that would have used it cannot know to,
// and the only callers left are stale ones and whoever is looking for a way
// in.
func checkDeprecatedFeatures(ctx context.Context, s *Session) Finding {
	c := s.check("protocol.deprecated_features", "Removed mechanisms are gone")
	if !s.Stateless() {
		// The generation itself is the finding here, and
		// handshake.protocol_era makes it. A server on a handshake revision
		// serving initialize is serving its own revision correctly.
		return c.skip("this server speaks a handshake revision, where initialize and ping are the protocol; handshake.protocol_era reports the generation")
	}

	var served []string
	for _, m := range removedMethods {
		id := s.nextID()
		rctx, cancel := s.stdioDeadline(telemetry.WithPhase(ctx, "protocol", "removed "+m.Method))
		rep, err := s.rawExchange(rctx, rawSend{Request: &transport.Request{
			JSONRPC: "2.0", ID: &id, Method: m.Method, Params: m.Params,
		}})
		cancel()
		if err == nil && replied(rep) {
			served = append(served, fmt.Sprintf("%s (%s)", m.Method, m.Was))
		}
	}

	declared := handshakeVersionsDeclared(s)
	if len(served) == 0 {
		if len(declared) > 0 {
			// It declares the older revisions and does not serve them. That
			// is worse than silence: a client will trust the declaration.
			return c.warn(
				fmt.Sprintf("supportedVersions declares %s, but neither initialize nor ping is answered", list(declared)),
				"remove the handshake revisions from supportedVersions, or implement them. A client that reads the declaration will negotiate down to a revision this server does not actually serve, and the failure lands on the first call rather than here")
		}
		return c.pass("neither initialize nor ping is answered: the mechanisms " + passmcp.StatelessVersions[0] + " removed are gone")
	}

	sort.Strings(served)
	c = c.ev(served...)
	if len(declared) > 0 {
		return c.pass(fmt.Sprintf("still answers %s, and declares %s in supportedVersions: older clients are supported deliberately",
			list(served), list(declared)))
	}
	return c.warn(
		fmt.Sprintf("still answers %s, which %s removed, and supportedVersions declares no handshake revision",
			list(served), passmcp.StatelessVersions[0]),
		"decide which this is. To keep serving older clients, list the handshake revisions in the server/discover result's supportedVersions so a client can negotiate down on purpose. To stop, remove the handlers — an endpoint no current client calls is reached only by stale software and by whoever is looking for one")
}

// handshakeVersionsDeclared is the handshake revisions the server said it
// speaks, which is what separates deliberate compatibility from residue.
func handshakeVersionsDeclared(s *Session) []string {
	if s.Era == nil || s.Era.Discovered == nil {
		return nil
	}
	var out []string
	for _, v := range s.Era.Discovered.SupportedVersions {
		if slices.Contains(passmcp.SessionVersions, v) {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// replied reports whether the exchange produced a result rather than a
// refusal. A -32601 is the answer this check wants to see, so it is not an
// error to report — it is the pass.
func replied(rep rawReply) bool {
	if rep.Response == nil || rep.Response.Error != nil {
		return false
	}
	// Over HTTP a 2xx is part of the answer; over a pipe there is no status
	// and the reply itself is the whole signal.
	return !rep.HTTP || rep.Status/100 == 2
}
