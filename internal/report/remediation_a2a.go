// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

// a2aRemediations is the guidance for passmcp a2a check, against an
// Agent2Agent agent.
var a2aRemediations = map[string]Remediation{
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
