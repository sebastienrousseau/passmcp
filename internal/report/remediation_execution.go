// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

// executionRemediations is the guidance for the checks that call tools,
// read resources and get prompts.
var executionRemediations = map[string]Remediation{
	// --- execution ---------------------------------------------------------

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
}
