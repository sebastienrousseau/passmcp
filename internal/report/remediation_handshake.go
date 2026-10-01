// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

// handshakeRemediations is the guidance for the handshake checks: the
// negotiated revision, the protocol era and what `initialize` returns.
var handshakeRemediations = map[string]Remediation{
	// --- handshake ---------------------------------------------------------

	"handshake.protocol_version": {
		Means: "The server answered `initialize` with 2024-11-05, the first " +
			"published revision of MCP. Version negotiation allows that, so " +
			"passmcp carries on, but the revision has none of what later ones " +
			"added: tool annotations and Streamable HTTP (2025-03-26), and " +
			"structured tool output and elicitation (2025-06-18). With no " +
			"`readOnlyHint`, no client can tell a lookup from a deletion, so a " +
			"cautious one, passmcp included, calls nothing.",
		Steps: []Step{
			{"Move to a current revision",
				"Answer `initialize` with the version the client offered when you " +
					"support it. 2025-06-18 or later gives you everything listed " +
					"above."},
			{"Annotate every tool",
				"Once on 2025-03-26 or later, declare `readOnlyHint: true` on each " +
					"tool that only reads, and `destructiveHint: false` on each that " +
					"changes state without destroying anything. That is what lets a " +
					"client call them without asking."},
		},
		Note: "Most SDKs negotiate the newest revision they know, so a server " +
			"answering 2024-11-05 is usually one built on an old SDK release; " +
			"updating the package is most of the work.",
	},

	"handshake.protocol_era": {
		Means: "MCP has two generations in the field. The older one opens with an " +
			"`initialize` request, and the server answers with an `Mcp-Session-Id` " +
			"that both sides then carry for the life of the connection. The " +
			"2026-07-28 revision removes that entirely: there is no handshake and " +
			"no session. Every request instead carries its own context, so a " +
			"server can answer any request without remembering the one before it.",
		Steps: []Step{
			{"Stop depending on initialize",
				"Remove the code that expects an initialization step, and anything " +
					"that stores or looks up per-session state keyed by " +
					"`Mcp-Session-Id`. On the current revision neither arrives."},
			{"Read the context out of _meta",
				"Each request carries the protocol version, the client's identity " +
					"and its capabilities in a `_meta` object on the request. That is " +
					"where the values you used to take from the initialize result now " +
					"live."},
			{"Route on the headers, not the body",
				"`Mcp-Method` and `Mcp-Name` mirror the method and the target name " +
					"outside the JSON. A gateway can route on them without parsing " +
					"the payload — but only if your server validates that they agree " +
					"with the body, which `protocol.routing_headers` checks."},
		},
		Note: "If you build on an official SDK, updating the package usually " +
			"carries the whole shift for you.",
	},

	"handshake.initialize": {
		Means: "The `initialize` request failed on a server that speaks a " +
			"handshake revision. Nothing after it can run: the protocol version and " +
			"the capability set are both settled here.",
		Steps: []Step{
			{"Read the error in the wire log",
				"An initialize that fails outright is usually a version " +
					"negotiation refusal or a malformed capabilities object, both of " +
					"which the response body names."},
		},
	},

	"handshake.stateless": {
		Means: "On the 2026-07-28 revision there is no `initialize`; a server " +
			"identifies itself through `server/discover` instead. This one answered " +
			"neither, so passmcp has no server identity or capability set to work " +
			"from.",
		Steps: []Step{
			{"Implement server/discover",
				"It is the stateless revision's replacement for the initialize " +
					"result, and the specification makes it a MUST."},
		},
	},

	"handshake.server_info": {
		Means: "The server did not identify itself, or gave a version of empty " +
			"string. Clients report that name and version in their own diagnostics, " +
			"and an operator looking at a misbehaving agent has nothing to go on.",
		Steps: []Step{
			{"Set name and version in serverInfo",
				"The version especially: it is what turns \"this server is " +
					"misbehaving\" into \"this build of this server is " +
					"misbehaving\"."},
		},
	},

	"handshake.capabilities": {
		Means: "The capabilities the server advertised do not match what it " +
			"actually serves — most often a capability declared and then not " +
			"implemented, or implemented and never declared. A client uses this " +
			"object to decide what to try.",
		Steps: []Step{
			{"Declare exactly what you implement",
				"An undeclared capability is one no careful client will use. A " +
					"declared one that fails is worse: it is discovered at the point " +
					"of use, in front of a user."},
		},
	},
}
