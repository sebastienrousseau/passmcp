// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

// catalogRemediations is the guidance for the checks on what the server
// lists: tools, resources, prompts and their schemas.
var catalogRemediations = map[string]Remediation{
	// --- catalog -----------------------------------------------------------

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
}
