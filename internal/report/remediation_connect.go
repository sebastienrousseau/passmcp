// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

// connectRemediations is the guidance for reaching the server and
// authenticating to it: network, discovery and authorization.
var connectRemediations = map[string]Remediation{
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

	// --- auth --------------------------------------------------------------

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
}
