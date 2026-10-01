// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

// protocolRemediations is the guidance for the JSON-RPC and transport
// conformance checks.
var protocolRemediations = map[string]Remediation{
	// --- protocol ----------------------------------------------------------

	"protocol.malformed_json": {
		Means: "A truncated or malformed request body was answered with a success " +
			"status. A client cannot distinguish that from a real answer, and a " +
			"proxy or a retry that corrupts a body will look like it worked.",
		Steps: []Step{
			{"Reject a body that does not parse",
				"Return HTTP 400, or the JSON-RPC `Parse error` code -32700. Either " +
					"tells the caller what happened; 200 does not."},
			{"Check the framing before the handler",
				"This usually belongs in the transport layer rather than in any " +
					"single tool, which is why it is easy to miss."},
		},
	},

	"protocol.invalid_params": {
		Means: "A request missing a required parameter was answered as though it " +
			"were valid. The parameter list is part of the contract; not enforcing " +
			"it means the contract is advisory.",
		Steps: []Step{
			{"Return -32602 for bad params",
				"`Invalid params` is the specified answer. Include which parameter " +
					"and why in the error message — that message reaches the model."},
		},
	},

	"protocol.unknown_tool": {
		Means: "Calling a tool that does not exist returned success. A client has " +
			"no way to tell a typo from a working call, and a model that " +
			"hallucinates a tool name is told it was right.",
		Steps: []Step{
			{"Return -32601 for an unknown method or tool",
				"`Method not found`. A model that receives an error learns the tool " +
					"does not exist; one that receives success learns the opposite."},
		},
	},

	"protocol.routing_headers": {
		Means: "`Mcp-Method` and `Mcp-Name` mirror the method and target outside " +
			"the JSON body so a gateway can route without parsing it. That only " +
			"buys anything if the server checks they agree with the body — " +
			"otherwise the gateway and the server can act on two different " +
			"requests, which is a confused-deputy waiting to happen.",
		Steps: []Step{
			{"Compare the headers to the body",
				"On every request, before dispatch."},
			{"Refuse a mismatch with -32020",
				"`HeaderMismatch` is the specified code. Refusing is the point: a " +
					"request whose envelope and body disagree has no correct " +
					"interpretation."},
		},
	},

	"protocol.extensions": {
		Means: "`server/discover` carries an `extensions` list, and every entry on " +
			"it is interface. passmcp's other checks exercise the base protocol, so " +
			"a server that advertises an extension is offering a surface this " +
			"report does not test — the enumeration exists so an operator knows " +
			"that surface is there. The identifiers are reverse-DNS because they " +
			"are a global namespace with no registry behind it: the domain is what " +
			"stops two authors meaning different things by the same word.",
		Steps: []Step{
			{"Name each extension after a domain you control",
				"`com.example.mcp/billing`, not `billing`. A bare word claims " +
					"nothing, so the next server to pick it collides with yours and " +
					"a client cannot tell which one it is talking to. " +
					"`io.modelcontextprotocol/…` belongs to the specification."},
			{"List each one once",
				"A duplicate is not harmless. A client that deduplicates and one " +
					"that does not will disagree about what the server offers, and " +
					"neither behaviour is wrong."},
			{"Advertise only what is implemented",
				"An extension in the list is a promise a client may act on before " +
					"it calls anything. Removing an extension from the list is a " +
					"smaller change than removing it from the list after a client " +
					"has built on it."},
		},
	},

	"protocol.deprecated_features": {
		Means: "The 2026-07-28 revision removed `initialize`, `ping` and the " +
			"session. A server on that revision that still answers the first two " +
			"is in one of two situations, and they look identical from outside: " +
			"either it deliberately serves older clients as well, or it is " +
			"carrying handlers no current client will call. `supportedVersions` in " +
			"the `server/discover` result is how a server says which of those it " +
			"is — so the finding is about the declaration, not about the handlers.",
		Steps: []Step{
			{"If older clients matter, declare the revisions",
				"Put the handshake revisions in `supportedVersions`. Then a client " +
					"negotiates down on purpose rather than discovering by accident " +
					"that `initialize` happens to work, and the compatibility is " +
					"something you can later remove on a schedule."},
			{"Otherwise remove the handlers",
				"An endpoint no current client calls still accepts requests. What " +
					"reaches it is stale software and whoever is enumerating the " +
					"server, and neither is traffic you are watching."},
			{"Do not declare what you do not serve",
				"The reverse is worse than silence: a client that reads " +
					"`supportedVersions` will negotiate to a revision the server " +
					"does not implement, and the failure lands on the first real " +
					"call instead of at discovery."},
		},
		Note: "Keeping both generations is legitimate and common. The check " +
			"passes when the server says so.",
	},

	"protocol.mrtr": {
		Means: "The 2026-07-28 revision removed server-initiated sampling, " +
			"elicitation and roots, and replaced them with Multi Round-Trip " +
			"Requests: when a server needs something from the client mid-call " +
			"it answers `resultType: input_required` with an `inputRequests` " +
			"object — keyed by request id — of client-side methods to invoke, " +
			"and/or an opaque `requestState`, and the client retries the " +
			"original call with the answers attached.\n\n" +
			"That only works if the request can be answered. An `input_required` " +
			"naming nothing and carrying no state, sent in a shape the client " +
			"does not read, or asking for something the client said it cannot " +
			"do, leaves no retry the client can construct — and the call does " +
			"not return an error, it simply never completes.\n\n" +
			"passmcp declares no client capabilities, so a conformant server can " +
			"only ever send it a retry carrying `requestState`. It does not " +
			"answer requests either way: it has no user to elicit from and no " +
			"model to sample. This check judges the results a run happened to " +
			"receive, and skips when none arrived.",
		Steps: []Step{
			{"Send inputRequests as an object keyed by request id",
				"The key is how the client says which answer belongs to which " +
					"request when it retries. An array is not a shape any revision " +
					"defines, so a client following the specification finds nothing " +
					"to answer."},
			{"Ask only for what the client declared",
				"Read the client capabilities on the request. Ask for " +
					"elicitation/create, sampling/createMessage or roots/list only " +
					"when the matching capability is declared, and for nothing else."},
			{"Carry at least one of inputRequests or requestState",
				"An empty result says \"I need something\" and not what; there is " +
					"no correct retry for it."},
			{"Do not ask on a liveness call",
				"`ping` exists to be answerable with nothing and nobody present. A " +
					"version of it that needs a user turns every liveness probe into " +
					"a conversation, and monitoring reads the server as down."},
		},
		Note: "A server that never needs client input is not missing anything. " +
			"This check skips rather than failing when no call asked.",
	},

	"protocol.unknown_method": {
		Means: "An unknown method did not return `-32601`. A client cannot tell an " +
			"unimplemented method from a broken one, and the model on the other " +
			"side learns nothing from the answer.",
		Steps: []Step{
			{"Return -32601 Method not found",
				"For any method you do not implement, including the optional ones."},
		},
	},

	"protocol.ping": {
		Means: "`ping` is how a client checks a connection is alive without " +
			"invoking anything. Without it, the only liveness signal is a real " +
			"call, which costs whatever that call costs.",
		Steps: []Step{
			{"Implement ping",
				"It returns an empty result. Note that the 2026-07-28 revision " +
					"removes it, so this applies to handshake-revision servers."},
		},
	},

	"protocol.id_echo": {
		Means: "A response came back with an id that does not match the request " +
			"that produced it. JSON-RPC uses that id to pair the two — a client " +
			"with several requests in flight will hand the wrong answer to the " +
			"wrong caller.",
		Steps: []Step{
			{"Echo the request id exactly",
				"Same value, same type. A numeric id must not come back as a " +
					"string."},
		},
	},

	"protocol.get_stream": {
		Means: "A GET on the MCP endpoint behaved unexpectedly for the revision " +
			"the server speaks. The handshake revisions serve a standalone event " +
			"stream there; 2026-07-28 removes it and expects `405`.",
		Steps: []Step{
			{"Match the revision you advertise",
				"Serving a stream a client no longer opens is harmless; refusing " +
					"one a client still needs is not."},
		},
	},

	"protocol.bogus_session": {
		Means: "The server answered a request carrying a session id it never " +
			"issued. A client that has lost its session cannot tell it has, so it " +
			"keeps sending a dead id instead of re-initializing.",
		Steps: []Step{
			{"Return 404 for an unknown session",
				"That is the signal a client uses to start a new one. Accepting an " +
					"unknown id silently is how a client gets stuck."},
		},
	},

	"protocol.tasks.unknown_id": {
		Means: "The server answered tasks/get for a task id it never issued, or " +
			"refused it with the wrong error. A client polling a mistyped or " +
			"expired id relies on -32602 to stop; without it, it polls forever.",
		Steps: []Step{
			{"Return -32602 for an unknown or expired task id",
				"The Tasks extension requires it for tasks/get. A purged task is " +
					"allowed to be unknown; it is not allowed to look alive."},
		},
	},

	"protocol.tasks.capability": {
		Means: "A task method was served, or refused with the wrong code, for a " +
			"client that did not declare the Tasks extension. -32021 is how a " +
			"client learns what it has to declare.",
		Steps: []Step{
			{"Check the declared capability before the task id",
				"Answer -32021 (Missing Required Client Capability) naming " +
					"io.modelcontextprotocol/tasks for tasks/get, tasks/update and " +
					"tasks/cancel from a client whose per-request capabilities omit it."},
		},
	},

	"protocol.tasks.undeclared": {
		Means: "The server returned a task to a client that never said it could " +
			"handle one. That client has no way to poll for the result, so the " +
			"call's answer is lost.",
		Steps: []Step{
			{"Return a task only when the request declares the extension",
				"Capabilities are per request on this revision. Without the " +
					"declaration, answer synchronously, or with -32021 if the call " +
					"genuinely cannot be served without a task."},
		},
	},

	"protocol.tasks.lifecycle": {
		Means: "A task passmcp followed broke the extension's contract: not " +
			"retrievable when its handle was returned, missing a required field, " +
			"never reaching a terminal state, or changing after it did. To an " +
			"agent each of these looks like a call that hangs or lies.",
		Steps: []Step{
			{"Create the task durably before returning its handle",
				"tasks/get for the returned id must resolve immediately, even in " +
					"an eventually consistent store."},
			{"Carry every required field",
				"taskId, status, createdAt, lastUpdatedAt and ttlMs (null for " +
					"unlimited) on every Task; result when completed, error when " +
					"failed, inputRequests when input_required; resultType " +
					"\"complete\" on the tasks/get answer."},
			{"Finish, and stay finished",
				"A task behind a read-only call should end promptly or report " +
					"progress in statusMessage. Once completed, failed or cancelled, " +
					"every later tasks/get must say the same."},
		},
		Note: "passmcp follows at most one task, created by calling a read-only " +
			"tool it has already called, and cancels any task it does not see " +
			"finish. A server that answers synchronously is not faulted: the " +
			"server decides per call whether to create a task.",
	},

	"protocol.origin": {
		Means: "The server answered a request whose Origin header named a site " +
			"it has no reason to trust. Through DNS rebinding, any web page the " +
			"user opens can point a hostname at this server's address and send it " +
			"requests from their browser, with whatever access that network " +
			"position gives.",
		Steps: []Step{
			{"Check Origin on every request, and refuse with 403",
				"Compare it against an allowlist of the origins your clients " +
					"actually use; a request with no Origin is a non-browser client " +
					"and is unaffected. The Streamable HTTP transport requires it."},
			{"Bind a local server to 127.0.0.1, not 0.0.0.0",
				"That keeps the rest of the network out. It does not keep a " +
					"browser on the same machine out, which is why the Origin check " +
					"is needed as well."},
		},
		Note: "A public endpoint only warns: the rule still applies, but DNS " +
			"rebinding is an attack on what a browser can reach that the " +
			"attacker cannot, which a public server is not.",
	},

	"protocol.notification_ack": {
		Means: "The server answered the `notifications/initialized` that " +
			"completes the handshake with something other than `202 Accepted` " +
			"and an empty body. A notification has no id, so there is no " +
			"response a client could match a body to; the Streamable HTTP " +
			"transport requires the bare acknowledgement, and a client that " +
			"reads what comes back is owed exactly that.",
		Steps: []Step{
			{"Answer an accepted notification with 202 and nothing else",
				"No JSON-RPC envelope, no `{}` and no event stream. A `200` or a " +
					"`204` is not the status the transport names."},
			{"Refuse only what you cannot accept, with a 4xx",
				"If the notification is rejected, the handshake is not complete " +
					"and the client has to be told so with an error status."},
		},
		Note: "Judged from the acknowledgement the handshake already received; " +
			"passmcp sends no extra notification to test this.",
	},

	"protocol.content_type": {
		Means: "A reply to a request was labelled something other than " +
			"`application/json` or `text/event-stream`, or carried no label at " +
			"all. Those are the only two the Streamable HTTP transport allows, " +
			"and a client that chooses how to read a reply by its header, as " +
			"the reference SDKs do, refuses anything else even when the body is " +
			"valid JSON-RPC. An HTML type usually means the request never " +
			"reached the MCP server: a sign-in page, an SSO or firewall " +
			"interstitial, or a path that is not the endpoint answered instead.",
		Steps: []Step{
			{"Set the header on every reply to a request",
				"`Content-Type: application/json` for one JSON object, or " +
					"`text/event-stream` when the reply is a stream."},
			{"If the type is HTML, check what sits in front of the server",
				"Exempt the MCP path from interactive sign-in and bot " +
					"challenges, and confirm the URL is the MCP endpoint rather " +
					"than a site root or documentation page."},
		},
	},

	"protocol.missing_session": {
		Means: "The server issued an `Mcp-Session-Id` at initialize, then served " +
			"a request that carried none. Either the session is not needed, in " +
			"which case issuing one only makes every client track state for " +
			"nothing, or it is needed and is not being enforced, so whatever the " +
			"session scopes is reachable without it.",
		Steps: []Step{
			{"Answer a request without the session id with 400",
				"The Streamable HTTP transport asks a server that requires a " +
					"session to refuse such a request with `400 Bad Request`; " +
					"`initialize` is the only request exempt."},
			{"Or stop issuing a session id",
				"A server that keeps no per-session state does not need one, " +
					"and a client then has nothing to lose or replay."},
		},
		Note: "passmcp sends one ping with its credentials and without the " +
			"session id, so a refusal can only be about the missing session.",
	},
}
