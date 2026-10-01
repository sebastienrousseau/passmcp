// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

// resilienceRemediations is the guidance for the performance and resilience
// checks.
var resilienceRemediations = map[string]Remediation{
	// --- performance -------------------------------------------------------

	"performance.ping": {
		Means: "The round-trip baseline is the cheapest call the server answers, " +
			"measured repeatedly. It is the floor under every other latency number " +
			"in this report — a slow baseline makes every tool look slow.",
		Steps: []Step{
			{"Compare cold and warm",
				"A large gap points at connection setup or a cold cache rather than " +
					"at the handler."},
		},
	},

	"performance.tools": {
		Means: "Tool latency was measured across repeated calls. A model waits for " +
			"these synchronously, and a slow tool is a slow agent — the cost lands " +
			"on the person watching a cursor blink.",
		Steps: []Step{
			{"Look at p95, not the mean",
				"The report gives both. An agent making several calls meets the " +
					"tail on most runs."},
		},
	},

	"performance.concurrency": {
		Means: "Calls failed under a modest parallel burst that succeeded " +
			"serially. That pattern points at shared mutable state or connection " +
			"handling rather than at load — the server is not slow, it is " +
			"incorrect under concurrency.",
		Steps: []Step{
			{"Look for state shared between requests",
				"A cached client, a reused buffer, a handler that is not reentrant. " +
					"The burst here is small; real agent traffic is larger."},
			{"If the failures are 429, send Retry-After",
				"Rate limiting is a correct answer. Rate limiting without telling " +
					"the client how long to wait is not."},
		},
	},

	"performance.rate_limit": {
		Means: "An unthrottled burst produced no rate limiting at all. That is " +
			"fine for a server you own, and a liability for one serving several " +
			"tenants: one misbehaving agent can consume the whole thing.",
		Steps: []Step{
			{"Consider a per-client limit",
				"With `Retry-After` on the 429, so a well-behaved client backs off " +
					"correctly rather than guessing."},
		},
	},

	// --- resilience --------------------------------------------------------

	"resilience.soak_memory": {
		Means: "With --soak, one tool that had succeeded was called again " +
			"hundreds of times and the server's resident memory was read from " +
			"/proc after each. Fitted through the samples after a warm-up, the " +
			"line rose steadily, by at least sixteen mebibytes and a quarter of " +
			"where it started, and was still rising at the end — or the server " +
			"stopped answering, or exited, part way through. A host keeps one process for the whole session, so " +
			"memory that only grows is a server that only runs for so long.",
		Steps: []Step{
			{"Find what a call allocates and never frees",
				"The usual suspects are a cache with no bound, a listener or " +
					"timer registered per request and never removed, and a " +
					"connection or file opened per call and not closed. Take a " +
					"heap profile after a hundred calls and after five hundred " +
					"and diff them; the growing type is the leak."},
			{"Bound every per-request structure",
				"Give caches a size and an eviction rule, and scope anything " +
					"created for a request to that request, so its end is the " +
					"end of the allocation."},
			{"Repeat the soak with --rps 0 against a server you own",
				"At the default pacing a thousand calls take about eight " +
					"minutes. Unthrottled they take seconds, and the trend is the " +
					"same measurement."},
		},
	},

	"resilience.upstream_down": {
		Means: "With every connection the server made held open and never " +
			"answered, as a hung dependency behaves, a tool call did not come " +
			"back within the call timeout, or the server exited. An agent " +
			"waiting on a call that will never finish cannot tell a slow " +
			"answer from a dead one, and waits for the host's whole timeout.",
		Steps: []Step{
			{"Put a timeout on every outbound call",
				"Shorter than the host's, so the tool gets to answer before the " +
					"host gives up on it."},
			{"Return the failure as a tool error",
				"`isError: true` with what failed, so the agent can say which " +
					"dependency is down and the next call still has a server."},
		},
		Note: "Only with --fault-upstream, over stdio. The proxy holds " +
			"connections rather than refusing them, because a refusal comes " +
			"back at once and hides a missing timeout.",
	},

	"resilience.session_reinit": {
		Means: "After its session was invalidated, the client could not recover. " +
			"Sessions end for ordinary reasons — a deploy, a timeout, a load " +
			"balancer moving the connection — and a client that cannot re-establish " +
			"one turns that into a user-visible failure.",
		Steps: []Step{
			{"Return 404 for a dead session",
				"That is the signal to re-initialize. Any other answer leaves the " +
					"client repeating a dead id."},
			{"Make re-initialization cheap",
				"It happens more often than the happy path suggests."},
		},
	},

	"resilience.token_refresh": {
		Means: "The token source could not renew. Tokens expire during long runs, " +
			"and a client that cannot refresh fails partway through work it has " +
			"already started.",
		Steps: []Step{
			{"Issue refresh tokens, or keep lifetimes long enough",
				"Either is defensible. What does not work is a short lifetime with " +
					"no way to renew."},
		},
	},

	"resilience.stateless": {
		Means: "The same request sent over two independent connections produced " +
			"different answers. Independence from the connection is what lets a " +
			"server sit behind a load balancer at all — without it, the second " +
			"request in a conversation may land on a machine that knows nothing " +
			"about the first.",
		Steps: []Step{
			{"Move per-connection state out of the process",
				"Anything remembered between requests belongs in a store both " +
					"replicas can reach, or nowhere."},
			{"Re-read the request context each time",
				"On the current revision every request carries what it needs in " +
					"`_meta`; there is no session to consult."},
		},
	},
}
