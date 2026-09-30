// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

import "strings"

// A finding tells somebody what is wrong. It does not tell them what to do,
// and the gap between those two is where a report stops being useful.
//
// "add outputSchema and return structuredContent" is correct and it assumes
// the reader already knows what changed, why it changed, and where in their
// code it lives. The person reading this report is often not the person who
// wrote the server, and is frequently reading it to decide whether to adopt
// the thing at all.
//
// So each entry here answers two questions in order: what does this mean,
// and what do I change. The steps are imperative and name the actual field,
// header or method — a step a reader cannot act on without a search engine
// is a step that has not been written yet.
//
// This is documentation, not observation. It is keyed by check id and
// attached at render time rather than carried on every Finding, because it
// is identical for every run and would otherwise be duplicated into every
// JSON report. remediation_test.go fails when a key here is not a real
// check id.

// Step is one imperative action, with the reason it is the action.
// The json tags matter: this type reaches a consumer through the report's
// `guidance` dictionary under --guidance, and every other field in that
// document is lower_snake. Exported Go names would have made this the one
// object in the report that is spelled differently.
type Step struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// Remediation is the guidance for one check.
type Remediation struct {
	// Means explains the finding in terms of the protocol, for a reader who
	// did not follow the specification change that produced it.
	Means string `json:"means"`
	// Steps are what to change, in the order they are worth doing.
	Steps []Step `json:"steps"`
	// Note is the shortcut, where one exists — usually that an SDK upgrade
	// does most of this. Saying so is not undermining the advice; it is the
	// difference between a report somebody acts on and one they postpone.
	Note string `json:"note,omitempty"`
}

// remediations is keyed by check id. Families are keyed by their literal
// prefix with the trailing dot, matching probe.DocFamilies.
var remediations = map[string]Remediation{
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

	"catalog.tools.output_schema": {
		Means: "`inputSchema` tells a client what arguments a tool takes. " +
			"`outputSchema` tells it what comes back. Without one, a result is " +
			"unvalidated text: the client cannot check it, cannot type it, and " +
			"cannot tell a malformed answer from a correct one — so the model is " +
			"left to interpret whatever arrives.",
		Steps: []Step{
			{"Declare outputSchema on each tool",
				"Ordinary JSON Schema, the same as `inputSchema`, describing the " +
					"shape of what the tool returns."},
			{"Return structuredContent, not prose",
				"Alongside the human-readable `content`, return a " +
					"`structuredContent` object that validates against the schema you " +
					"just declared. Returning a flat string leaves the client nothing " +
					"to check."},
			{"Keep them honest",
				"passmcp validates `structuredContent` against `outputSchema` on every " +
					"call it makes; a schema that does not describe the real result is " +
					"worse than none, because it is now a promise."},
		},
		Note: "Updating the SDK gives you the type definitions, which will flag " +
			"every tool still missing either half.",
	},

	"catalog.tools.descriptions": {
		Means: "A description is not documentation for a person. It is the text " +
			"the model reads when deciding which tool to call, and it is the only " +
			"thing distinguishing two tools with similar names. A thin one gets " +
			"the tool called at the wrong moment, or not at all.",
		Steps: []Step{
			{"Say what it does and when to use it",
				"One or two sentences: the action, the inputs that matter, and the " +
					"situation it is for. \"Searches\" is not a description; " +
					"\"Search the customer directory by email or account number\" is."},
			{"Say what it returns",
				"A caller choosing between two tools is choosing between two " +
					"results."},
			{"Name the limits",
				"Rate limits, maximum page sizes and required permissions belong " +
					"here — the model has no other way to learn them."},
		},
	},

	"catalog.budget.tokens": {
		Means: "Every tool a client can reach is loaded into the model's context " +
			"before it decides anything, on every call, and it is billed that way. " +
			"A large catalogue costs money on each request and makes the model " +
			"choose worse: retrieval degrades as the number of candidates grows, " +
			"so the twentieth tool does not just cost tokens, it makes the other " +
			"nineteen harder to pick between.",
		Steps: []Step{
			{"Look at the three largest first",
				"The finding names them. Catalogue weight is almost never evenly " +
					"spread — a couple of tools with deeply nested schemas usually " +
					"account for most of it."},
			{"Cut what is not needed to choose the tool",
				"A schema has two jobs: helping the model decide whether to call " +
					"this tool, and validating the call. Only the first is paid for " +
					"on every request. Deep nesting, exhaustive enums and long " +
					"examples can often move into the description or into the error " +
					"the server returns when an argument is wrong."},
			{"Split the server, or page the catalogue",
				"A server with ninety tools is usually several servers. Where it " +
					"genuinely is not, progressive discovery lets a client fetch the " +
					"catalogue in parts rather than all of it at connection time."},
		},
		Note: "The token figure is an estimate — passmcp counts characters and divides " +
			"by four, and says so in the finding. The byte count beside it is exact; " +
			"tokenise that with your own model if you need the precise number. " +
			"Model families tokenize differently and several tokenizers are " +
			"unpublished, so passmcp embeds none (ADR 0009).",
	},

	"catalog.semantic.ambiguity": {
		Means: "A parameter with a type and no description tells the model nothing " +
			"about what to put in it. The call is still well-formed, so the " +
			"protocol is satisfied and nothing fails a conformance check — the " +
			"model simply guesses, and the failure surfaces later as a wrong " +
			"answer rather than as an error. A required parameter is the acute " +
			"case: the model has to supply it.",
		Steps: []Step{
			{"Describe every required parameter first",
				"One sentence saying what the value is and where the caller gets " +
					"it. `id` is not a description; \"the account id from " +
					"list_accounts\" is, and it tells the model which other tool to " +
					"call first."},
			{"Constrain what you can",
				"An `enum` removes a whole class of guesses. A `pattern`, a " +
					"`format`, a numeric bound or a `default` each narrow the space " +
					"the model is choosing from, and all of them are cheaper than the " +
					"prose that would otherwise be needed."},
			{"Add an example where the shape is not obvious",
				"`examples` on a property costs a few tokens and removes the " +
					"most common category of malformed call: the right type in the " +
					"wrong shape."},
		},
	},

	"catalog.tools.annotations": {
		Means: "Annotations are how a tool declares whether calling it is safe. " +
			"`readOnlyHint` says it only reads; `destructiveHint` says it can " +
			"destroy something. A tool with no annotations is treated by the " +
			"specification as destructive, which is why passmcp will not call it " +
			"and why a cautious client will not either.",
		Steps: []Step{
			{"Annotate every read-only tool",
				"Set `readOnlyHint: true` on anything that only reads. This is the " +
					"single change that most increases what a client is willing to do " +
					"unattended."},
			{"Be explicit about the rest",
				"Set `destructiveHint` honestly on anything that deletes or " +
					"overwrites. An unannotated tool and a destructive one are the " +
					"same thing to a careful caller, so silence costs you nothing but " +
					"usage."},
		},
	},

	"execution.validation": {
		Means: "The tool accepted a call with a required argument missing. The " +
			"schema said the argument was required and the server did not enforce " +
			"it, which means the schema is describing an intention rather than a " +
			"contract. A model that gets a plausible answer to an incomplete call " +
			"has no way to learn it made a mistake.",
		Steps: []Step{
			{"Validate arguments against your own schema",
				"Before the tool body runs, check the arguments against the " +
					"`inputSchema` you published. Most SDKs will do this for you if " +
					"you let them."},
			{"Fail with -32602",
				"Return the JSON-RPC `Invalid params` error rather than a success " +
					"with a guess in it. An error the model can read is a correction; " +
					"a plausible wrong answer is not."},
		},
	},

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

	"catalog.text.encoded": {
		Means: "A field in the catalogue carries base64 that decodes to readable " +
			"text. This is the evasion route around every other check in this " +
			"family: a reviewer skimming the tool list sees an opaque blob and " +
			"moves on, and the model — asked to be helpful — is entirely capable " +
			"of decoding it and acting on what it says. A tool description has no " +
			"honest reason to carry one.",
		Steps: []Step{
			{"Decode it and read it",
				"The finding includes the decoded text. If it is an instruction " +
					"aimed at the model, this is a tool-poisoning payload and the " +
					"question is how it got into your catalogue rather than how to " +
					"reword it."},
			{"If it is yours, write it out",
				"Configuration, a sample payload or an encoded example belongs " +
					"somewhere a person reviewing the catalogue can read it. If it is " +
					"genuinely binary, describe it in prose and put the bytes behind " +
					"a resource."},
			{"If it is not yours, treat it as an incident",
				"Check who can write tool metadata, when this field last changed, " +
					"and whether any other server in your fleet carries the same " +
					"blob. A payload encoded to survive review was put there by " +
					"somebody who expected review."},
		},
		Note: "Only runs that decode to text are reported. Hashes, identifiers and " +
			"genuine binary decode to noise and are passed over, so a finding here " +
			"means something wrote a sentence and then hid it.",
	},

	"stdio.clean_exit": {
		Means: "The server was still running after its stdin closed, and had " +
			"to be signalled. Closing the pipe is how a host ends a stdio " +
			"session — it is the documented shutdown and there is no other " +
			"one — so a server that carries on is a server the host has to " +
			"kill, every session, forever.",
		Steps: []Step{
			{"Treat EOF on stdin as the stop signal",
				"The read loop returning end-of-file is the session ending. " +
					"Finish what is in flight, flush, and exit; do not wait " +
					"for a signal that a well-behaved host will not send " +
					"first."},
			{"Handle SIGTERM as well, not instead",
				"A host that has waited its grace period signals before it " +
					"kills. A server that ignores both loses whatever it had " +
					"not written."},
			{"Count the processes after a few sessions",
				"This is the defect that shows up as a developer machine with " +
					"eleven copies of the same server on it, none of which any " +
					"host still has a handle to."},
		},
	},

	"stdio.no_zombie": {
		Means: "The server exited and processes it had started were still " +
			"running in its process group. Nothing else in the report " +
			"notices: the server handshook, served its catalogue and shut " +
			"down cleanly. The worker it left behind still holds what it was " +
			"given — a port, a lock, the credentials from its environment — " +
			"and there is no longer anything that knows how to stop it.",
		Steps: []Step{
			{"Reap what you spawn",
				"Keep a handle on every child and wait for it during " +
					"shutdown. A worker started for one session should not " +
					"outlive that session."},
			{"Kill the group, not the leader",
				"If the children are not tracked individually, put them in a " +
					"process group and signal the group on the way out."},
			{"Do not rely on the host",
				"passmcp killed this one, because leaving it running would be a " +
					"worse defect than reporting it. A host will not: it closes " +
					"the pipe and forgets the server existed."},
		},
		Note: "Only asked when the server exited on its own. If it had to be " +
			"signalled, its whole group went with it and what it left behind " +
			"cannot be told apart from what the signal stopped, so the check " +
			"skips rather than guessing. Platforms without POSIX process " +
			"groups skip it too.",
	},

	"supply.provenance": {
		Means: "The server binary was built from a working tree with " +
			"uncommitted changes. Go records that as `vcs.modified=true`, " +
			"and it means the source this binary was made from does not " +
			"exist in the repository: no commit describes it, so no review " +
			"of that repository describes what is actually running.",
		Steps: []Step{
			{"Build from a clean checkout",
				"In CI that is usually already true. A dirty stamp on a " +
					"release artifact almost always means it was built on " +
					"somebody's laptop."},
			{"Keep the revision",
				"A binary built from a commit carries it, and that one field " +
					"is what turns \"we reviewed the code\" into a statement " +
					"about the thing that is running."},
			{"Where dependencies carry no checksum, find out why",
				"A module with no `h1:` sum did not come through the module " +
					"proxy and the checksum database never saw it — a local " +
					"`replace` or a vendored tree. Neither can be verified " +
					"after the fact."},
		},
		Note: "Read out of the binary with `debug/buildinfo`, so it is one " +
			"of the few things in this report the server cannot influence by " +
			"answering differently. Only for a stdio target: an endpoint is a " +
			"URL, and a URL is not a file passmcp can open. A build from a " +
			"source archive carries no stamp at all, which is reported as an " +
			"observation rather than as a dirty build.",
	},

	"fs.credential_probe": {
		Means: "The server opened a credential file in its home directory " +
			"that it was never given and never asked about. passmcp planted " +
			"those files: they are decoys containing nothing real, and the " +
			"home directory the server saw was a scratch one. Nothing was " +
			"lost here. The same code against an operator's own machine " +
			"reads their actual keys.",
		Steps: []Step{
			{"Find the read",
				"The finding names which decoys were opened. A server that " +
					"reads ~/.ssh/id_rsa or ~/.aws/credentials has a code path " +
					"that goes looking for credentials outside the ones it was " +
					"configured with, and that path is worth reading."},
			{"Ask whether it is a library",
				"Some SDKs load ambient cloud credentials by default. That is " +
					"still a server reaching for something nobody gave it, and " +
					"it still deserves to be deliberate rather than a default " +
					"nobody noticed."},
			{"Check what left",
				"`fs.canary_exfiltrated` answers the second half. A read with " +
					"nothing leaving is a smaller problem than a read followed " +
					"by a request."},
		},
		Note: "This rests on file access times, and a great many filesystems " +
			"do not record them — macOS on APFS does not, and Linux mounted " +
			"`noatime` does not. passmcp measures whether the witness works " +
			"before trusting it and reports that it cannot tell rather than " +
			"reporting a clean result it is not entitled to.",
	},

	"fs.canary_exfiltrated": {
		Means: "The contents of a planted credential file left. This is not " +
			"an inference: each decoy contains a string that exists nowhere " +
			"else, and that exact string was seen in an outbound request " +
			"body, on the server's own stderr, or handed back to passmcp in a " +
			"result. The file was read and its contents were sent.",
		Steps: []Step{
			{"Treat it as an incident, not a finding",
				"Whatever reads a decoy key and transmits it reads a real one " +
					"and transmits that. The finding names the file and where " +
					"the contents went."},
			{"Find the code before the server runs anywhere real",
				"It may be deliberate, it may be a logging statement that " +
					"dumps an environment, and the two are not the same " +
					"problem — but both send a credential somewhere it does " +
					"not belong."},
			{"Assume any real credential is compromised",
				"If this server has already run against a machine with real " +
					"keys, rotate them rather than reasoning about whether " +
					"this particular path was taken."},
		},
		Note: "Seen over plain HTTP, on stderr, and on the pipe back to " +
			"passmcp. A tunnel is opaque on purpose: passmcp reads a CONNECT " +
			"destination and never the payload, because the alternative is " +
			"installing a certificate authority to decrypt traffic it was " +
			"not asked to decrypt. Over https the destination is reported by " +
			"`egress.hosts` and the payload is not.",
	},

	"egress.undeclared_host": {
		Means: "The server connected to a host that `--expect-egress` does " +
			"not name. passmcp saw it because it started the process and " +
			"pointed its proxy settings at a listener of its own, which is " +
			"the only way to see a destination that appears in no manifest, " +
			"no catalogue and no documentation — a destination nobody " +
			"declared is not declared on purpose.",
		Steps: []Step{
			{"Find out what the host is",
				"The finding names it and says how many times it was reached. " +
					"A CDN, a telemetry endpoint and an exfiltration target all " +
					"look the same from here; only somebody who knows the " +
					"server can tell them apart."},
			{"Add it if it is a dependency",
				"`--expect-egress api.example.com`, repeatable, and a leading " +
					"dot matches subdomains. An expectation that is written " +
					"down is one the next run enforces."},
			{"Treat an unexplained host as an incident",
				"A server that contacts somewhere its author cannot account " +
					"for, on a run where it was handed tool arguments, is the " +
					"case this check exists for. Check what it was given before " +
					"the connection."},
		},
		Note: "Watched only with `--watch-egress`, and only over stdio, " +
			"because it works by setting the child's environment. Two blind " +
			"spots worth knowing: a destination on the same machine is not " +
			"seen, since almost every runtime refuses to proxy loopback, and " +
			"a client that ignores the proxy environment entirely is not seen " +
			"either.",
	},

	"catalog.cache_hints": {
		Means: "The tools/list result says nothing about being cached. Every " +
			"client fetches your catalogue again on every session, and then " +
			"pays for it in context on every call after that. The 2026-07-28 " +
			"revision lets you stop the first half of that with two optional " +
			"fields, and this server sets neither.",
		Steps: []Step{
			{"Set ttlMs on the list result",
				"How many milliseconds a client may keep the answer. Minutes " +
					"is usually right: long enough to cover a session, short " +
					"enough that a catalogue change reaches clients the same " +
					"day."},
			{"Set cacheScope when the catalogue is the same for everyone",
				"`public` lets a shared client cache one copy for all users. " +
					"Leave it unset, or say `private`, when what a user sees " +
					"depends on who they are -- an over-shared catalogue is a " +
					"worse problem than a re-fetched one."},
			{"Pair it with the catalogue's size",
				"`catalog.budget.tokens` says what the catalogue costs to " +
					"look at. This says whether anyone has to pay it twice."},
		},
		Note: "Both fields are optional, so this warns only on a catalogue " +
			"large enough for re-fetching to cost something, and is an " +
			"observation otherwise. It is skipped entirely before 2026-07-28, " +
			"where there is nothing to state.",
	},

	"catalog.baseline": {
		Means: "The catalogue is not the one recorded in the baseline file. " +
			"Something about this server changed after somebody approved it, " +
			"which is the shape of the threat a one-shot diagnostic cannot " +
			"see: a server passes review and edits its tool descriptions the " +
			"following week.",
		Steps: []Step{
			{"Read the diff before deciding",
				"The finding quotes both sides. What changed is the finding, " +
					"not that something did -- a new optional property and a " +
					"`readOnlyHint` becoming true are not the same event and are " +
					"not reported at the same severity."},
			{"Approve it if it is yours",
				"`passmcp check --baseline .passmcp/baseline.json --approve` writes " +
					"the catalogue this run saw as the new baseline. Approving is " +
					"a decision a person makes after reading the diff, which is " +
					"why it is a separate flag and not something a run does on " +
					"its own."},
			{"Treat an unexplained change as an incident",
				"A tool that gained `readOnlyHint: true`, a description that " +
					"acquired text aimed at the model, or a required argument " +
					"that quietly disappeared are each worth asking the operator " +
					"about before the next agent session runs against it."},
		},
		Note: "Severity is by kind, never by count. A `readOnlyHint` flipping " +
			"to true is critical because it makes cautious clients -- passmcp " +
			"included -- start invoking a tool they previously refused. A new " +
			"optional property is reported as information, because a gate that " +
			"cries wolf over one is a gate somebody switches off.",
	},

	"execution.payload_size": {
		Means: "A tool answered with more text than a caller can afford. A " +
			"result is not a file somebody downloads: it goes into the " +
			"model's context, whole, on the call that asked for it. A " +
			"hundred kilobytes is a large share of a small window spent on " +
			"one reply, and the caller cannot refuse delivery -- by the time " +
			"the size is known, the answer has already arrived.",
		Steps: []Step{
			{"Page it",
				"Return a cursor and let the caller ask for more. A tool that " +
					"expects to be called again is one a model can use " +
					"without gambling its whole window on the first call."},
			{"Or truncate it and say so",
				"A result cut at a sensible size with a line admitting it was " +
					"cut is honest and usable. One that is silently complete " +
					"but enormous is neither."},
			{"Or hand back a reference",
				"For genuinely large output, return a resource URI the caller " +
					"can fetch in parts, rather than inlining it."},
		},
		Note: "A large result that says it was paginated or truncated is " +
			"reported as an observation rather than a warning: the size is " +
			"then a choice somebody made. Only a large result with no sign of " +
			"being bounded is worth acting on. Nothing here costs an extra " +
			"request -- the execution phase already made these calls and " +
			"already counted the bytes.",
	},

	"execution.error_guidance": {
		Means: "A tool rejected a call and the rejection said nothing the " +
			"caller could act on — a bare \"error\", or an internal stack " +
			"trace. The caller here is a model, and the error string is the " +
			"entire recovery path it has: it cannot read your logs, open your " +
			"source, or ask a colleague.",
		Steps: []Step{
			{"Say what was wrong with which argument",
				"\"path must be absolute\" and \"state must be one of open, " +
					"closed, all\" are each one retry away from a working call. " +
					"\"Invalid input\" ends the attempt."},
			{"Never return the exception",
				"A trace is unusable to the caller and hands it your file " +
					"layout, framework and often your dependency versions, on a " +
					"path anyone who can call the tool can reach. Log the trace; " +
					"return the reason."},
			{"Point at the tool that would help",
				"If recovery means calling something else first, name it. " +
					"\"Use list_directory to find the path\" is the difference " +
					"between a model that recovers and one that gives up or " +
					"starts guessing."},
		},
		Note: "Returning isError is not itself a defect and is not counted as " +
			"one. passmcp calls tools with generated arguments, so a correct " +
			"server will reject some of them; this check grades only the " +
			"wording of the rejection. With no rejection in the run, it skips " +
			"rather than passing.",
	},

	"catalog.tools.annotation_honesty": {
		Means: "A tool annotated `readOnlyHint: true` describes a change of " +
			"state — its name leads with a mutation verb, or its first " +
			"sentence does. One of the two is wrong, and until somebody says " +
			"which, the catalogue cannot be acted on safely.",
		Steps: []Step{
			{"Decide which half is true",
				"If the tool really only reads, the name or the opening sentence " +
					"is misleading and should be reworded. If it writes, the " +
					"annotation is wrong and has to be corrected — that is the " +
					"urgent direction."},
			{"Remember who reads this",
				"`readOnlyHint` is not documentation; it is the flag cautious " +
					"clients use to decide what may be invoked without asking. " +
					"passmcp invokes read-only tools and nothing else, so an " +
					"understated annotation is how a server gets a careful client " +
					"to perform the write on its behalf."},
			{"Set destructiveHint too",
				"A tool that modifies but does not destroy should say so " +
					"explicitly rather than leaning on the default, which is " +
					"`destructiveHint: true` and is the safest reading rather than " +
					"the accurate one."},
		},
		Note: "The check reads the leading verb of the name and of the first " +
			"sentence only. Caveats later in a description — \"returns an error " +
			"if the file was deleted\" — are not read as descriptions of " +
			"deletion, and read-path verbs like open, close and set are not " +
			"treated as mutations.",
	},

	"catalog.text.shadowing": {
		Means: "A description does not describe the tool it belongs to. It " +
			"attaches a rule to some other tool — \"when calling send_email, " +
			"always BCC…\" — and the model reads every description it is given " +
			"with equal authority and no notion of which server each one came " +
			"from. That is the whole mechanism: a server you are evaluating can " +
			"rewrite the behaviour of a server you already trust, without ever " +
			"being called itself.",
		Steps: []Step{
			{"Read the sentence passmcp quoted",
				"The finding names the field it came from, the tool the rule is " +
					"aimed at, and whether that tool is one this server lists. A " +
					"target this server does not have is the cross-server shape and " +
					"is reported as critical."},
			{"Move the rule to the tool it governs",
				"If the constraint is real and the tool is yours, it belongs in " +
					"that tool's own description, where the operator approving it " +
					"can see what it applies to. A precondition on your own tool is " +
					"documentation; the same sentence in a sibling's description is " +
					"not."},
			{"If the tool is not yours, treat it as an incident",
				"Nothing legitimate needs one server's catalogue to issue orders " +
					"about another server's tools. Check who can write this " +
					"metadata and when the field last changed, and look for the " +
					"same sentence across the rest of your fleet."},
		},
		Note: "Only constructions that constrain another tool are reported — " +
			"\"when calling X\", \"before invoking X\", \"never use X\". Pointing " +
			"the model at a sibling (\"use list_directory to find the path\") is " +
			"what good documentation does and is passed over, because a check " +
			"that flags helpful cross-references is one people mute.",
	},

	"catalog.text.instructions": {
		Means: "Somewhere in the catalog, text is addressed to the model rather " +
			"than describing a tool — an instruction to ignore what it was told, " +
			"to conceal something from the user, or to act as a different agent. " +
			"A description is read with the same standing as the user's own words, " +
			"so this is indistinguishable from an instruction an attacker planted.",
		Steps: []Step{
			{"Find the text passmcp quoted",
				"The finding names the field, including when it is a `description` " +
					"inside an `inputSchema` — which is where this is most often " +
					"found, because it is the part nobody renders."},
			{"Rewrite it as a description",
				"Say what the tool does. If it genuinely needs a precondition, that " +
					"belongs in the schema as a required argument, not in prose " +
					"aimed at the model."},
			{"Find out how it got there",
				"If nobody on the team wrote it, the question is no longer a " +
					"wording one."},
		},
	},

	"catalog.text.comments": {
		Means: "Catalog text contains an HTML comment. A catalog viewer renders " +
			"the description and hides the comment; the model receives the raw " +
			"string and reads both. That gap is the whole attraction — a comment " +
			"is the one place to put text a reviewer will not see and the model " +
			"will.",
		Steps: []Step{
			{"Read what the comment says",
				"passmcp quotes it in the finding. A leftover note and an instruction " +
					"aimed at the model look identical in a diff and are not the " +
					"same problem."},
			{"Move it or delete it",
				"If it belongs in the description, put it there, where a person " +
					"approving the tool will see it. If it does not, it does not " +
					"belong in text the model reads either."},
		},
	},

	"catalog.text.hidden": {
		Means: "The catalog contains characters a reviewer cannot see — " +
			"zero-width spaces, or bidirectional overrides that reorder how text " +
			"displays without changing what is read. The model reads the real " +
			"sequence. Anyone auditing the catalog reads the rendered one.",
		Steps: []Step{
			{"Strip the characters passmcp listed",
				"The finding gives their code points and shows them in context as " +
					"`<U+200B>`-style escapes."},
			{"Ask why they are there",
				"A bidirectional override in a tool description has no honest " +
					"explanation. Zero-width characters occasionally arrive by " +
					"accident through a copy-paste from a rich-text editor."},
		},
	},

	"catalog.text.secret_paths": {
		Means: "Catalog text names a place credentials live — an SSH key, an AWS " +
			"credentials file, a token environment variable. That may be accurate " +
			"and expected. It is also exactly what a poisoned description says " +
			"when it is trying to get one read and returned.",
		Steps: []Step{
			{"Confirm the tool really does this",
				"If it does, say so in prose an operator approves before installing, " +
					"not in a schema field."},
			{"If it does not, delete the reference",
				"A description that names a credential path it never touches is " +
					"either a leftover or a probe."},
		},
	},

	"catalog.names.confusable": {
		Means: "A name mixes scripts — Latin with Cyrillic or Greek letters that " +
			"render identically. That is not how a name is written by accident; " +
			"it is how one tool is made to look like another the user already " +
			"trusts.",
		Steps: []Step{
			{"Rename it in a single script",
				"The finding names which scripts were mixed."},
			{"Check what it resembles",
				"The interesting question is which existing tool the rendered name " +
					"matches."},
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

	// --- net ---------------------------------------------------------------

	"net.dns": {
		Means: "The hostname did not resolve. Nothing else in the run could be " +
			"attempted, because there was no address to connect to — every later " +
			"phase is skipped rather than failed.",
		Steps: []Step{
			{"Check the name, then the resolver",
				"A typo and a missing DNS record look identical from here. If the " +
					"name is right, the record may be internal-only, in which case " +
					"the run needs to happen from inside that network."},
		},
	},

	"net.scheme": {
		Means: "The endpoint is plain HTTP. Everything the client sends — the " +
			"bearer token above all — crosses the network readable by anything on " +
			"the path.",
		Steps: []Step{
			{"Serve the endpoint over TLS",
				"Then move the client to the https URL. An http endpoint that " +
					"redirects to https still exposes the first request, including " +
					"its Authorization header."},
		},
		Note: "Loopback is exempt and passmcp treats it as such: a local development " +
			"server on http is not a finding.",
	},

	// --- stdio: the checks that only a child-process run can make ---------

	"stdio.process": {
		Means: "The program passmcp was told to run exited before it answered a " +
			"single request. Nothing after this could be tested, so the rest of " +
			"the report is empty rather than clean — a host starting this server " +
			"would see the same thing and report that the server is unavailable.",
		Steps: []Step{
			{"Run the command yourself, exactly as passmcp did",
				"The report names it, including the arguments. A server that exits " +
					"immediately almost always says why on stderr, and the finding " +
					"carries whatever it said."},
			{"Check what it needed that it did not get",
				"The three usual causes are a missing argument, a working directory " +
					"it did not expect, and an environment variable it reads at " +
					"startup. passmcp passes a fixed base environment and nothing " +
					"else, so a server that needs a credential must be given it by " +
					"name with --stdio-env."},
			{"Make the failure legible",
				"Exit with a message on stderr that names what was missing. A host " +
					"has no other channel: it sees a process that died, and an " +
					"operator sees a client that will not connect."},
		},
	},

	"stdio.alive": {
		Means: "The server was running when the run started and had exited before " +
			"it finished. A host keeps one process for a whole session, so an exit " +
			"partway through does not end one request — it ends every conversation " +
			"that process was holding, and the user sees their assistant lose the " +
			"ability to use the server mid-task.",
		Steps: []Step{
			{"Find the last request it answered",
				"Run with --report-dir and read the telemetry: the last recorded " +
					"message is the one it died on or just after. What the server " +
					"wrote to stderr is in the finding's evidence."},
			{"Handle the failure instead of exiting",
				"An unhandled exception in a tool handler, an assertion, or a " +
					"deliberate exit on bad input all present identically to a host. " +
					"Return a JSON-RPC error, or an isError result, and stay up."},
			{"Do not exit on a message you did not understand",
				"An unknown method, a malformed body and an unexpected " +
					"notification are all things a client will legitimately send. " +
					"Answering with an error is correct; dying is not."},
		},
	},

	"stdio.stdout_clean": {
		Means: "The server wrote something to stdout that was not a JSON-RPC " +
			"message. Over stdio, stdout is the wire: every byte on it is parsed " +
			"as protocol framing. One banner, one print statement left in a " +
			"handler, or a progress bar is enough to corrupt the stream, and the " +
			"client cannot recover — it sees a parse error, or nothing at all.",
		Steps: []Step{
			{"Send every log line to stderr",
				"passmcp keeps stderr and reports it; nothing is lost by moving it " +
					"there. In most languages this is one change to the logger's " +
					"destination, and it is the whole fix."},
			{"Look for the ones that are not logging",
				"A framework's startup banner, a dependency that prints on import, " +
					"a deprecation warning from the runtime, a debugger left " +
					"attached. The finding quotes the first line it saw, which is " +
					"usually enough to identify the source."},
			{"Keep stdout for the transport, permanently",
				"Redirect the process's own stdout to stderr at startup, before " +
					"anything else runs, and write protocol messages through the " +
					"handle you saved. Then a stray print by anything you depend on " +
					"cannot break the transport."},
		},
		Note: "This is the single most common way a working server appears broken " +
			"to a host, because the symptom never names the cause.",
	},

	"auth.unauthenticated_tools": {
		Means: "The server answered a tools/list carrying no token, no API key and " +
			"no basic auth, and the catalogue it returned includes at least one " +
			"tool that is not declared read-only. By the specification's own " +
			"default a tool with no annotations is destructive, so anyone who can " +
			"reach this endpoint can invoke it. This is the most common serious " +
			"finding in the ecosystem: a measurement study of 7,973 live remote " +
			"servers found 40.55% exposing tools with no authentication at all.",
		Steps: []Step{
			{"Require authorization before the catalogue, not only before the call",
				"An unauthenticated tools/list discloses what the system can do — " +
					"tool names and descriptions map your internal capabilities for " +
					"anyone who asks. Answer 401 with a WWW-Authenticate challenge " +
					"pointing at your protected-resource metadata, as RFC 9728 " +
					"describes, and let a client discover how to authenticate rather " +
					"than discovering what you can do."},
			{"Check enforcement at the handler, not at the router",
				"The common shape of this bug is a middleware that protects " +
					"tools/call and not tools/list, or that protects a path prefix " +
					"the MCP endpoint does not sit under. The finding names which " +
					"tools came back, which tells you exactly which handler answered."},
			{"Annotate honestly while you are there",
				"Every tool named in this finding lacks readOnlyHint:true. If one " +
					"of them really is read-only, say so — it will stop being " +
					"reported here and cautious clients will start being willing to " +
					"call it. If it is not read-only, the finding is correct and " +
					"authorization is the fix."},
		},
		Note: "On loopback this is a warning rather than a failure, because an open " +
			"development server is ordinary. It stops being ordinary the moment the " +
			"endpoint is reachable from anywhere else — including through a tunnel.",
	},

	"net.tcp": {
		Means: "The address resolved but the connection was refused or timed out. " +
			"The server is not listening where DNS says it is, or something between " +
			"here and there is dropping the connection.",
		Steps: []Step{
			{"Confirm what is listening on that port",
				"From a machine that can reach it. A firewall that drops rather " +
					"than rejects presents as a timeout, not a refusal."},
		},
	},

	"net.tls": {
		Means: "The TLS handshake failed, or the certificate did not verify for " +
			"this hostname. passmcp does not skip verification — a diagnostic that " +
			"ignores a bad certificate is telling you the connection is fine when " +
			"it is not.",
		Steps: []Step{
			{"Fix the chain, or the name",
				"An incomplete chain and a certificate for the wrong hostname are " +
					"the two common causes. The finding says which."},
			{"Check the expiry while you are there",
				"passmcp records the certificate's remaining lifetime in the " +
					"telemetry for every connection it makes."},
		},
	},

	"net.tls.cert": {
		Means: "The certificate has expired, or is close enough to expiry to be " +
			"worth acting on now. An expired certificate does not degrade " +
			"gracefully: every client stops connecting at the same moment, and the " +
			"first anyone hears of it is an outage.",
		Steps: []Step{
			{"Renew it",
				"The finding gives the remaining lifetime in days, which is also " +
					"recorded per connection in the telemetry."},
			{"Automate the renewal if it is not already",
				"A certificate that needed a person to remember is a certificate " +
					"that will expire on a weekend."},
		},
	},

	"net.tls.version": {
		Means: "The connection negotiated TLS 1.1 or older. Those versions are " +
			"deprecated and are being removed from clients — a server on one of " +
			"them will stop being reachable rather than become insecure.",
		Steps: []Step{
			{"Enable TLS 1.3, require 1.2 as the floor",
				"Both are widely supported. The only thing older versions buy is " +
					"compatibility with clients that should not be connecting to a " +
					"credentialed endpoint anyway."},
		},
	},

	// --- discovery ---------------------------------------------------------

	"discovery.first_contact": {
		Means: "The endpoint did not answer a JSON-RPC POST. Before any " +
			"authorization is attempted, passmcp makes one unauthenticated request to " +
			"see how the server asks to be authenticated; this is that request " +
			"failing outright.",
		Steps: []Step{
			{"Accept a POST at the endpoint",
				"Even unauthenticated, the answer should be an HTTP-level refusal " +
					"with a challenge — not a connection error, a redirect to a login " +
					"page, or an HTML error document."},
			{"Replace HTTP+SSE with Streamable HTTP",
				"When the finding says the server speaks the 2024-11-05 HTTP+SSE " +
					"transport, the POST was refused because that transport takes " +
					"messages at a second URL it announces in an `endpoint` event. " +
					"Streamable HTTP replaced it in 2025-03-26: one endpoint that " +
					"accepts POST. Current SDKs provide it, and most can keep the old " +
					"SSE and POST endpoints alongside it for older clients."},
		},
		Note: "A server that can also run as a program can be checked over stdio " +
			"in the meantime: `passmcp check --stdio -- <command>`.",
	},

	"discovery.challenge": {
		Means: "The server demands authorization but does not say how to obtain " +
			"it. RFC 9728 expects a `WWW-Authenticate` header naming the protected " +
			"resource metadata, which is how a client finds the authorization " +
			"server without being configured by hand.",
		Steps: []Step{
			{"Return a challenge on 401",
				"`WWW-Authenticate: Bearer resource_metadata=\"https://…/" +
					".well-known/oauth-protected-resource\"`. Without it every client " +
					"needs out-of-band setup."},
		},
	},

	"discovery.prm": {
		Means: "Protected resource metadata is the document that tells a client " +
			"which authorization server issues tokens for this endpoint. Without " +
			"it, discovery stops and the operator has to supply the token endpoint " +
			"by hand.",
		Steps: []Step{
			{"Serve the metadata document",
				"At `/.well-known/oauth-protected-resource`, listing " +
					"`authorization_servers`."},
		},
	},

	"discovery.prm.resource": {
		Means: "The metadata names a `resource` that is not this endpoint. RFC " +
			"9728 requires a client to verify that binding, because metadata that " +
			"can claim to speak for any endpoint is metadata that can redirect a " +
			"token to the wrong one. passmcp refuses rather than warns.",
		Steps: []Step{
			{"Make resource match the endpoint it describes",
				"Exactly. If one document legitimately serves several endpoints, " +
					"each needs its own."},
		},
	},

	"discovery.as": {
		Means: "The authorization server's metadata could not be fetched or " +
			"parsed. That document carries the token and authorization endpoints, " +
			"so nothing after it can proceed.",
		Steps: []Step{
			{"Serve RFC 8414 or OIDC metadata",
				"At `/.well-known/oauth-authorization-server` or " +
					"`/.well-known/openid-configuration` on the issuer named in the " +
					"protected resource metadata."},
		},
	},

	"discovery.as.https": {
		Means: "A discovered authorization endpoint is plain HTTP. Everything " +
			"after the first document is chosen by the server under test, so an " +
			"http URL here would send a client secret across the network in the " +
			"clear. passmcp refuses to follow it.",
		Steps: []Step{
			{"Serve every discovered endpoint over HTTPS",
				"`--insecure-allow-http-auth` exists for local development and is a " +
					"deliberate override, not a fix."},
		},
	},

	"discovery.as.pkce": {
		Means: "The authorization server does not advertise PKCE with S256. MCP " +
			"clients are required to use PKCE, so a server that does not advertise " +
			"it either does not support it or is not saying so — and a client " +
			"cannot tell which.",
		Steps: []Step{
			{"Advertise S256",
				"`code_challenge_methods_supported: [\"S256\"]` in the metadata. " +
					"`plain` is not sufficient."},
		},
	},

	"discovery.registration": {
		Means: "Dynamic client registration lets a client obtain its own " +
			"credentials rather than being configured with a shared one. Without " +
			"it, every client needs a secret provisioned by hand.",
		Steps: []Step{
			{"Advertise registration_endpoint",
				"Or accept that each client is registered manually — which is a " +
					"defensible choice, and one worth stating in your own " +
					"documentation."},
		},
	},

	"discovery.creds_unused": {
		Means: "Credentials were supplied and the server never asked for any. The " +
			"run succeeded, but the endpoint is open: anything that can reach it " +
			"can use it.",
		Steps: []Step{
			{"Confirm that is intended",
				"An endpoint meant to be public is fine. One that was meant to be " +
					"protected and is not is the most serious thing in this report, " +
					"whatever its severity says."},
		},
	},

	"discovery.assemble": {
		Means: "The discovered documents could not be assembled into a usable " +
			"authorization configuration — the pieces were each fetchable but do " +
			"not fit together.",
		Steps: []Step{
			{"Read the error, then the metadata",
				"The finding carries the specific inconsistency. It is most often " +
					"an issuer that disagrees between the two documents."},
		},
	},

	"discovery.override.build": {
		Means: "The endpoints supplied on the command line — `--token-url`, " +
			"`--auth-url` — could not be turned into a working configuration. This " +
			"is about the override, not the server.",
		Steps: []Step{
			{"Check the overriding flags",
				"They bypass discovery entirely, so a typo here is not corrected by " +
					"anything the server says."},
		},
	},

	// --- auth --------------------------------------------------------------

	"auth.token": {
		Means: "No token could be obtained, so every phase that needs one was " +
			"skipped. Either no credentials were supplied for a server that " +
			"requires them, or the exchange itself failed.",
		Steps: []Step{
			{"Supply what the server asked for",
				"The discovery phase above says which mode the server advertises. " +
					"`--token-env` for a pre-issued token, `--auth " +
					"client-credentials` with `--client-secret-env` for a machine " +
					"client."},
			{"Read the exchange in the wire log",
				"The token endpoint's own error message is in the recorded " +
					"requests, and is usually more specific than the finding."},
		},
	},

	"auth.registration": {
		Means: "Dynamic client registration was attempted and failed. passmcp " +
			"registers a client when the server advertises the endpoint and no " +
			"client id was supplied.",
		Steps: []Step{
			{"Check what the registration endpoint returned",
				"It is in the wire log. Servers commonly reject registration " +
					"because of a redirect URI policy, which the error names."},
		},
	},

	"auth.token.type": {
		Means: "The token endpoint returned a `token_type` other than Bearer. A " +
			"client that assumes Bearer will send the wrong Authorization scheme " +
			"and be refused.",
		Steps: []Step{
			{"Return token_type: Bearer",
				"Unless the endpoint genuinely issues another type, in which case " +
					"the clients that can use it are the ones written for it."},
		},
	},

	"auth.token.expiry": {
		Means: "The token endpoint did not return `expires_in`, so a client cannot " +
			"tell how long the token is good for. It has to wait for a 401 and " +
			"retry, which turns a refresh into a user-visible failure.",
		Steps: []Step{
			{"Return expires_in",
				"Seconds, alongside the token. Clients then refresh before expiry " +
					"rather than after."},
		},
	},

	"auth.token.scope": {
		Means: "The granted scope is narrower than the scope requested. Calls that " +
			"need the missing permission will fail later, at the point of use, " +
			"with an error that does not obviously point back here.",
		Steps: []Step{
			{"Grant the scope, or stop advertising it",
				"A client that asks for what the server advertises and receives " +
					"less has no way to discover which calls will now fail."},
		},
	},

	"auth.rejects_garbage": {
		Means: "The server accepted an obviously invalid token. Whatever it is " +
			"doing with the Authorization header, it is not verifying it — which " +
			"means the endpoint is effectively unauthenticated.",
		Steps: []Step{
			{"Verify the token before handling the request",
				"Signature, issuer, audience and expiry. This is the most serious " +
					"class of finding passmcp produces, because every other " +
					"authorization control is downstream of it."},
		},
	},

	// --- handshake ---------------------------------------------------------

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

	// --- protocol ----------------------------------------------------------

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

	"catalog.tools.idempotency": {
		Means: "A tool declared read-only also declared that repeating it is " +
			"unsafe. A read cannot have a second effect, so the second hint only " +
			"stops a client from retrying a call that timed out.",
		Steps: []Step{
			{"Make the two hints agree",
				"Drop idempotentHint: false from a read-only tool, or drop " +
					"readOnlyHint if the call does change something."},
			{"Declare idempotentHint on tools that change state",
				"Set it true when a repeated identical call has no further effect, " +
					"so an agent can retry after a timeout without doing the work twice."},
		},
	},

	"discovery.dpop": {
		Means: "What the resource and its authorization server say about " +
			"proof-of-possession does not hold together. DPoP (RFC 9449) binds a " +
			"token to a key the client keeps, so a copied token is useless to " +
			"whoever copied it — but only if the proof algorithms are asymmetric " +
			"and a client can find out, from the metadata and the refusal, that " +
			"a bound token is required.",
		Steps: []Step{
			{"List asymmetric proof algorithms only",
				"`dpop_signing_alg_values_supported: [\"ES256\"]`, never `none` or " +
					"an `HS*` MAC."},
			{"Advertise the requirement where a client looks for it",
				"When the resource sets `dpop_bound_access_tokens_required`, the " +
					"authorization server lists its DPoP algorithms and the 401 " +
					"carries a `DPoP` challenge."},
		},
		Note: "Read from metadata only. MCP's DPoP profile (SEP-1932) is a draft, " +
			"so a server without DPoP is recorded, not marked down.",
	},

	"discovery.enterprise_managed": {
		Means: "The authorization server advertises the Identity Assertion JWT " +
			"Authorization Grant that MCP's Enterprise-Managed Authorization " +
			"extension uses, but its token endpoint does not list the grant type " +
			"the ID-JAG is presented with. An enterprise client that trusts the " +
			"profile will be refused at the last step.",
		Steps: []Step{
			{"List the JWT bearer grant",
				"Add `urn:ietf:params:oauth:grant-type:jwt-bearer` to " +
					"`grant_types_supported`, or stop advertising the profile."},
		},
	},

	"stdio.post_init_connections": {
		Means: "After its handshake the server held a socket to a non-loopback " +
			"address that did not go through passmcp's proxy. After the handshake " +
			"every action is one a request caused, and a connection made around " +
			"HTTP_PROXY is invisible to egress.hosts, so this is the destination " +
			"passmcp could not name.",
		Steps: []Step{
			{"Reach the network through the configured proxy",
				"Use an HTTP client that honours HTTP_PROXY and HTTPS_PROXY, so " +
					"an operator can see and govern where the server goes."},
			{"Connect only for the call that needs it",
				"A read-only lookup that opens a socket to an address nobody " +
					"configured is the shape exfiltration takes, whatever the intent."},
		},
		Note: "Seen by sampling /proc on Linux; a connection opened and closed " +
			"between two samples is not seen, so no finding is not a guarantee.",
	},

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

	"stdio.post_init_writes": {
		Means: "After its handshake the server held a file open for writing " +
			"outside the working directory it was started in. A tool call should " +
			"not leave the server writing to the user's home or system paths.",
		Steps: []Step{
			{"Write under the working directory, or a configured path",
				"Put caches and state where the host told the server to run, or " +
					"where the operator named in configuration."},
		},
		Note: "Seen by sampling /proc on Linux; passmcp's scratch home and /dev, " +
			"/proc and /sys are not reported.",
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

	// --- catalog -----------------------------------------------------------

	"catalog.tools.list": {
		Means: "The server declared a tools capability and then failed to list " +
			"them. Nothing in the execution phase can run, and a client will meet " +
			"the same error at the point it tries to use the server at all.",
		Steps: []Step{
			{"Implement tools/list, or stop declaring the capability",
				"A declared capability is a promise the client will act on."},
		},
	},

	"catalog.resources.list": {
		Means: "Resources were advertised and could not be listed. The same shape " +
			"as the tools case: a declared capability is a promise the client acts " +
			"on, and this one is not kept — so a client meets the error at the " +
			"moment it tries to use the server.",
		Steps: []Step{
			{"Implement resources/list, or drop the capability",
				"Whichever is true. A server with no resources and no resources " +
					"capability is correct; one that advertises and then fails is a " +
					"broken promise."},
		},
	},

	"catalog.prompts.list": {
		Means: "Prompts were advertised and could not be listed. A client reads " +
			"the capability set to decide what to offer, so a prompts capability " +
			"that cannot be enumerated produces a menu entry leading nowhere.",
		Steps: []Step{
			{"Implement prompts/list, or drop the capability",
				"A capability nobody can enumerate is one nobody can use."},
		},
	},

	"catalog.tools.unique": {
		Means: "Two tools share a name. Which one a call reaches is undefined, and " +
			"a model choosing between them is choosing between two identical " +
			"labels.",
		Steps: []Step{
			{"Make names unique",
				"The finding lists the duplicates. If they come from different " +
					"upstreams merged into one server, prefix them."},
		},
	},

	"catalog.tools.input_schema": {
		Means: "An `inputSchema` is not a JSON Schema object. A client cannot " +
			"generate arguments for it, cannot validate them, and in most SDKs will " +
			"not offer the tool at all.",
		Steps: []Step{
			{"Make every inputSchema type: object",
				"Even a tool with no arguments has an object schema with no " +
					"properties. The finding names which tools are wrong."},
		},
	},

	"catalog.tools.schema_valid": {
		Means: "A tool's `inputSchema` or `outputSchema` is not valid JSON Schema " +
			"2020-12 in a part a client reads: a `type` that is not one of the " +
			"seven JSON types, a `required` that is not a list of names, a " +
			"`properties` entry that is not a schema, or a `$ref` that points at " +
			"nothing. A client builds and checks arguments from these schemas; " +
			"one it cannot read is a tool it cannot call correctly, and many " +
			"SDKs drop the tool rather than guess.",
		Steps: []Step{
			{"Go to the pointer the finding names",
				"Each entry reads `tool field#/json/pointer: problem`. The pointer " +
					"is relative to that schema's root, so `#/properties/q/type` is " +
					"the `type` of the `q` property."},
			{"Generate schemas rather than write them by hand",
				"A schema derived from the handler's own parameter types (zod, " +
					"pydantic, a Go struct) cannot drift into an invalid shape. " +
					"Validate the published catalogue against the 2020-12 " +
					"meta-schema in your own tests."},
			{"Declare every required property",
				"A name in `required` that `properties` does not declare is valid " +
					"JSON Schema, and a client generating arguments has no type for " +
					"it. Declare it, or drop it from `required`."},
		},
		Note: "Unknown keywords are only noted: JSON Schema ignores them, and " +
			"so does every client passmcp knows of.",
	},

	"catalog.tools.order": {
		Means: "Two `tools/list` requests made one after the other returned the " +
			"same tools in a different order. The specification does not require " +
			"an order, but a client puts the tools into the model's context in the " +
			"order it received them, so a server that reshuffles changes the " +
			"prompt prefix on every connection and every prompt cache keyed on it " +
			"misses: more latency and more cost for every agent, for no change in " +
			"the catalogue.",
		Steps: []Step{
			{"Return tools in a fixed order",
				"Sort by name, or keep registration order, before building the " +
					"`tools/list` result. The usual cause is iterating a hash map, " +
					"whose order a runtime randomises on purpose."},
			{"Keep pages stable too",
				"When the list is paginated, the same cursor should return the " +
					"same page. The finding cites both listings, so the two orders " +
					"can be compared in the wire log."},
		},
	},

	"catalog.resources.uris": {
		Means: "A resource URI is relative. A client has nothing to resolve it " +
			"against — the resource list is not a web page and there is no base.",
		Steps: []Step{
			{"Make resource URIs absolute",
				"With a scheme. Custom schemes are fine; relative paths are not."},
		},
	},

	"catalog.prompts.descriptions": {
		Means: "Prompts, or their arguments, are undescribed. The same problem as " +
			"an undescribed tool: the description is what the model reads to decide " +
			"whether this is the prompt it wants.",
		Steps: []Step{
			{"Describe each prompt and each argument",
				"What it produces, and what the argument is for."},
		},
	},

	"catalog.tools.title": {
		Means: "Tools have no human-readable `title`. The name is an identifier " +
			"meant for matching; the title is what a person reads when picking " +
			"from a list, and what a client shows in a consent prompt before " +
			"letting an agent call something.",
		Steps: []Step{
			{"Add a title to each tool",
				"Short, in sentence case, describing the action rather than " +
					"restating the identifier."},
		},
	},

	"catalog.empty": {
		Means: "The server exposes no tools, no resources and no prompts. There is " +
			"nothing for an agent to use — whatever else is correct, the catalog is " +
			"the product.",
		Steps: []Step{
			{"Check the capability declaration and the listing",
				"An empty catalog is usually a server that failed to register its " +
					"tools at startup rather than one that has none."},
		},
	},

	// --- execution ---------------------------------------------------------

	"execution.tools": {
		Means: "Every tool passmcp called returned an error. The catalog is " +
			"well-formed and nothing in it works, which a client discovers only at " +
			"the point of use.",
		Steps: []Step{
			{"Read one failing call in the wire log",
				"Each finding cites the request. A single failing call usually " +
					"explains all of them — a missing upstream credential, most " +
					"often."},
		},
	},

	"execution.content": {
		Means: "A tool returned `structuredContent` that does not validate against " +
			"its own `outputSchema`. The schema is a promise to the client about " +
			"what it can rely on, and this one is not kept.",
		Steps: []Step{
			{"Validate before returning",
				"Against the schema you published. The finding gives the JSON " +
					"pointer to the part that did not match."},
			{"Fix whichever is wrong",
				"Sometimes it is the result. Sometimes the schema drifted from the " +
					"code and nobody noticed, which is the more common of the two."},
		},
	},

	"execution.resources": {
		Means: "A resource read returned no contents. A client cannot tell that " +
			"apart from a broken read, so it will either retry or present an empty " +
			"document as though it were the answer.",
		Steps: []Step{
			{"Return contents, or an error",
				"An empty success is the one answer that carries no information."},
		},
	},

	"execution.resources.uri": {
		Means: "A `resources/read` answered with contents filed under a different " +
			"`uri` from the one requested, or with no `uri` at all. Every item in " +
			"`contents` carries the URI of what it is, and a client holding " +
			"several resources at once matches contents to requests by that " +
			"field. Contents under another URI are attached to the wrong " +
			"resource, or dropped.",
		Steps: []Step{
			{"Echo the requested URI",
				"Set `contents[].uri` to exactly the string the client sent in " +
					"`params.uri`. Do not canonicalise it on the way back: a " +
					"trailing slash or a changed case is a different key to the " +
					"client."},
			{"Keep sub-resources distinguishable",
				"A read that returns several items, such as a directory's " +
					"children, may give each its own URI, but the resource asked " +
					"for should be among them. The finding cites the read that " +
					"showed the mismatch."},
		},
	},

	"execution.prompts": {
		Means: "A prompt rendered with no messages. There is nothing for the model " +
			"to receive, so the prompt is unusable however well it is described.",
		Steps: []Step{
			{"Return at least one message",
				"Or report an error if the arguments given cannot produce one."},
		},
	},

	"execution.prompts.validation": {
		Means: "A prompt that declares a required argument was rendered without " +
			"it, or refused with something other than JSON-RPC `-32602` " +
			"(Invalid params), which is the error the specification names for a " +
			"missing required argument. A prompt rendered without its input " +
			"hands the model a template with a hole in it; a refusal a client " +
			"cannot classify cannot be turned into a request for the missing " +
			"value.",
		Steps: []Step{
			{"Check arguments before rendering",
				"Compare `params.arguments` in `prompts/get` with the prompt's " +
					"declared `arguments`, and stop before rendering when one marked " +
					"`required` is absent."},
			{"Refuse with -32602",
				"Return a JSON-RPC error with code `-32602` and a message naming " +
					"the missing argument, not an HTTP error and not a server-error " +
					"code. The finding cites the request, and the per-prompt result " +
					"records what came back."},
		},
		Note: "Most SDKs validate prompt arguments for you when the prompt is " +
			"registered with its argument list rather than parsed by hand.",
	},

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

	// --- the attack classes research shows are exploited (#7) -----------

	"auth.wrong_audience": {
		Means: "The server accepted a token its own authorization server issued " +
			"for a different resource. Any token that authorization server mints " +
			"for any other API therefore works here, which is how a token leaked " +
			"from one service becomes access to this one.",
		Steps: []Step{
			{"Check the audience of every token",
				"Reject a token whose aud does not name this server's canonical " +
					"URI. The MCP authorization specification requires it, and " +
					"RFC 8707 resource indicators are how a client asks for the " +
					"right audience."},
			{"Never forward the client's token upstream",
				"If the server calls other APIs, it obtains its own token for " +
					"them; passing the client's through is what makes audience " +
					"checks matter."},
		},
	},

	"catalog.text.cross_server_shadowing": {
		Means: "A tool description refers to tools another configured server " +
			"exposes, steering the agent towards them or changing how they are " +
			"used. Descriptions are read by the model, so one server can redirect " +
			"calls meant for another without either server being called.",
		Steps: []Step{
			{"Describe only this server's tools",
				"Remove every reference to other servers and their tools from " +
					"descriptions, schemas and prompts."},
			{"Document integrations where the model does not read them",
				"If the servers are meant to work together, say so in the " +
					"README, not in text the agent treats as instructions."},
		},
	},

	"catalog.toxic_combination": {
		Means: "One server exposes both a tool that reads private or local data " +
			"and a tool that sends data out or writes externally. A single " +
			"injected instruction can then read something private and send it " +
			"away, with no second server involved.",
		Steps: []Step{
			{"Split the capabilities",
				"Put the reading tools and the outbound tools in separate servers " +
					"with separate credentials, so an agent has to be given both."},
			{"Mark and restrict the outbound tool",
				"Annotate it with openWorldHint and destructiveHint as they apply, " +
					"so hosts can ask for confirmation, and limit where it can send."},
		},
		Note: "This is a warning, not a failure: the combination can be " +
			"intended. The question is whether an agent should hold both at once.",
	},

	"execution.output_injection": {
		Means: "A read-only tool returned text shaped like instructions to the " +
			"model. Tool output reaches the model's context, so whoever controls " +
			"the data the tool reads can steer the agent through it.",
		Steps: []Step{
			{"Return untrusted content as data",
				"Quote or escape fetched text, return it in structuredContent " +
					"with a clear field name, and do not echo it into anything the " +
					"model reads as guidance."},
			{"Strip or label directives from external sources",
				"Where the content is known to be untrusted, say so in the result " +
					"rather than passing it through as the tool's own words."},
		},
	},

	"stdio.bind_all": {
		Means: "The server, started over stdio, also opened a listening socket " +
			"on every network interface. Anything on the same network can reach " +
			"it, although the host only ever meant to talk to it over a pipe.",
		Steps: []Step{
			{"Do not listen at all",
				"A stdio server needs no socket. Remove the listener, or make it " +
					"opt-in."},
			{"If a socket is needed, bind to loopback and require authentication",
				"127.0.0.1 or ::1, never 0.0.0.0 or ::."},
		},
	},

	"stdio.launch_config": {
		Means: "The client configuration starts the server in a way that runs " +
			"more than it says: through a shell, by piping a download into one, " +
			"from a package with no pinned version, or with a secret on the " +
			"command line where every process on the machine can read it.",
		Steps: []Step{
			{"Pin the package",
				"npx pkg@1.2.3 or uvx pkg==1.2.3, so a new release is a change " +
					"you review rather than one that arrives on the next start."},
			{"Run the program directly",
				"Name the executable and its arguments; do not wrap them in " +
					"sh -c or pipe a download into a shell."},
			{"Pass secrets in the environment",
				"Arguments are visible in the process list; the env block of the " +
					"configuration is not."},
		},
	},

	// --- a2a: passmcp a2a check, against an Agent2Agent agent ---------------

	"a2a.transport": {
		Means: "The Agent Card is served over plain HTTP from a host other than " +
			"this machine. The card, and every credential a client then sends to " +
			"the interfaces it names, cross the network readable and alterable by " +
			"anything on the path.",
		Steps: []Step{
			{"Serve the agent and its card over TLS",
				"A2A requires HTTPS for its HTTP-based bindings in production. " +
					"Publish the card at https://<domain>/.well-known/agent-card.json " +
					"and point every supportedInterfaces url at an https URL."},
		},
		Note: "Loopback is exempt: a local agent on http is recorded, not failed.",
	},

	"a2a.card_schema": {
		Means: "The Agent Card could not be fetched from the well-known path, or " +
			"it is not a valid A2A v1 AgentCard. A client that parses the card " +
			"strictly rejects it, and one that parses it loosely may read a " +
			"field the agent did not mean.",
		Steps: []Step{
			{"Publish the card at the well-known path",
				"Serve it as JSON at /.well-known/agent-card.json on the agent's " +
					"domain, answering 200."},
			{"Fix each path the finding names",
				"Every error carries its JSON path, such as $.skills[0].tags. " +
					"Compare it with the AgentCard message in the A2A v1 " +
					"specification; a field from A2A 0.3, such as url or " +
					"preferredTransport, is reported as unknown."},
		},
	},

	"a2a.card_signature": {
		Means: "The card carries a signature that does not verify, or verifies " +
			"only against a key embedded in its own header. A card that fails to " +
			"verify may have been altered after signing; one signed by a key it " +
			"carries itself proves nothing about who published it.",
		Steps: []Step{
			{"Sign the canonical form",
				"Remove default values, exclude the signatures member, " +
					"canonicalise with RFC 8785 (JCS), and sign that as the JWS " +
					"payload. Re-sign after every change to the card."},
			{"Publish the key where the header says",
				"Name the key set with jku and the key with kid in the protected " +
					"header, and serve the JWKS over HTTPS from the agent's domain."},
		},
		Note: "An unsigned card is not failed: signing is optional in A2A v1.",
	},

	"a2a.unauthenticated": {
		Means: "The agent answered a request that carried no credentials, or " +
			"refused one while its card declares no security scheme. The first " +
			"means anyone can read the agent's tasks; the second means a client " +
			"cannot learn from the card how to authenticate.",
		Steps: []Step{
			{"Enforce authentication on every method",
				"Answer 401 to a request without credentials, on read methods " +
					"such as ListTasks as well as on SendMessage."},
			{"Declare what you enforce",
				"List the scheme in securitySchemes and require it in " +
					"securityRequirements, so a client knows what to send."},
		},
		Note: "passmcp makes exactly one call to show this: ListTasks with a page " +
			"size of one and no credentials. It never sends a message or invokes " +
			"a skill.",
	},
}

// RemediationFor returns the guidance for a check id.
//
// A family instance resolves to its family, the same way probe.DocURL does,
// because the guidance is about the family and the instance is whatever this
// particular server happened to have.
func RemediationFor(id string) (Remediation, bool) {
	if r, ok := remediations[id]; ok {
		return r, true
	}
	for key := range remediations {
		if strings.HasSuffix(key, ".") && strings.HasPrefix(id, key) {
			return remediations[key], true
		}
	}
	return Remediation{}, false
}
