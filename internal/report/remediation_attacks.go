// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

// attackRemediations is the guidance for the attack classes research
// shows are exploited (#7).
var attackRemediations = map[string]Remediation{
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
}
