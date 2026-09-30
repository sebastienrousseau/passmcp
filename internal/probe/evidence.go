// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import "strings"

// ADR-0002 in code: a finding passes only on evidence.
//
// A check records the requests it made (req#N-M) and, where the evidence
// is an observation rather than a request, says what it saw (the addresses
// a name resolved to, the certificate's subject). A pass with neither is
// a verdict nobody can check, and the score is derived from findings, so
// check.done does not let one through: it is recorded as info instead,
// with a note saying why.
//
// The ADR names one exception. Some checks judge what an earlier request
// in the same run returned — uniqueness of tool names is decided from the
// tools/list response — and make no request of their own. Those are listed
// here, each with where its evidence is, so an exception is a line a
// reviewer reads rather than a pass nobody notices. Adding a check to this
// list is a claim about where its evidence lives; if it has none, it
// belongs in info.

// derivedChecks maps a check id, or a family prefix ending in ".", to
// where the evidence for its pass is recorded.
var derivedChecks = map[string]string{
	// The endpoint and the network phase's own handshake.
	"net.scheme":      "the endpoint URL the operator named",
	"net.tls":         "the TLS handshake the net phase performed",
	"net.tls.version": "the TLS handshake the net phase performed",

	// Documents fetched by discovery and the exchange auth made.
	"discovery.prm.resource": "the protected resource metadata cited by discovery.prm",
	"discovery.as.pkce":      "the authorization server metadata cited by discovery.as",
	"discovery.registration": "the authorization server metadata cited by discovery.as",
	"auth.registration":      "the registration the auth phase performed",
	"auth.token.type":        "the token response cited by auth.token",
	"auth.token.expiry":      "the token response cited by auth.token",
	"auth.token.scope":       "the token response cited by auth.token",

	// The initialize exchange.
	"handshake.protocol_version": "the initialize exchange cited by handshake.initialize",
	"handshake.protocol_era":     "the initialize exchange cited by handshake.initialize",
	"handshake.server_info":      "the initialize exchange cited by handshake.initialize",
	"handshake.capabilities":     "the initialize exchange cited by handshake.initialize",
	"handshake.instructions":     "the initialize exchange cited by handshake.initialize",
	"handshake.session":          "the initialize exchange cited by handshake.initialize",

	// The catalogue as listed.
	"catalog.tools.unique":             "the tools/list responses cited by catalog.tools.list",
	"catalog.tools.descriptions":       "the tools/list responses cited by catalog.tools.list",
	"catalog.tools.input_schema":       "the tools/list responses cited by catalog.tools.list",
	"catalog.tools.annotations":        "the tools/list responses cited by catalog.tools.list",
	"catalog.tools.annotation_honesty": "the tools/list responses cited by catalog.tools.list",
	"catalog.names.confusable":         "the tools/list responses cited by catalog.tools.list",
	"catalog.toxic_combination":        "the tools/list responses cited by catalog.tools.list",
	"catalog.semantic.ambiguity":       "the tools/list responses cited by catalog.tools.list",
	"catalog.cache_hints":              "the list responses cited by the catalog.*.list findings",
	"catalog.baseline":                 "the tools/list responses cited by catalog.tools.list",
	"catalog.text.":                    "the list responses cited by the catalog.*.list findings",
	"catalog.prompts.descriptions":     "the prompts/list responses cited by catalog.prompts.list",
	"catalog.resources.uris":           "the resources/list responses cited by catalog.resources.list",

	// Summaries of the calls a phase made, each recorded in the telemetry
	// under that phase and listed per tool in the report.
	"execution.tools":          "the tools/call requests the execution phase made",
	"execution.content":        "the tools/call requests the execution phase made",
	"execution.validation":     "the tools/call requests the execution phase made",
	"execution.payload_size":   "the tools/call requests the execution phase made",
	"execution.error_guidance": "the tools/call requests the execution phase made",
	"execution.resources":      "the resources/read requests the execution phase made",
	"execution.prompts":        "the prompts/get requests the execution phase made",
	"performance.ping":         "the timed calls the performance phase made",
	"performance.warmup":       "the timed calls the performance phase made",
	"performance.tools":        "the timed calls the performance phase made",
	"performance.concurrency":  "the timed calls the performance phase made",

	// What passmcp observed of a process it started or a proxy it ran.
	"stdio.alive":            "the server process passmcp started",
	"stdio.stdout_clean":     "the server process's stdout, read for the whole run",
	"stdio.clean_exit":       "the server process's exit, observed at close",
	"stdio.no_zombie":        "the server process group, observed at close",
	"fs.credential_probe":    "the access times of the decoys planted for the run",
	"fs.canary_exfiltrated":  "the decoys planted for the run and every exchange recorded",
	"egress.hosts":           "the connections the egress proxy recorded",
	"egress.undeclared_host": "the connections the egress proxy recorded",
}

// derivedBasis says where a derived check's evidence is recorded, and
// whether id is one.
func derivedBasis(id string) (string, bool) {
	if basis, ok := derivedChecks[id]; ok {
		return basis, true
	}
	for prefix, basis := range derivedChecks {
		if strings.HasSuffix(prefix, ".") && strings.HasPrefix(id, prefix) {
			return basis, true
		}
	}
	return "", false
}

// unevidenced reports whether f is a pass with no evidence of its own that
// is not a derived check: the finding ADR-0002 forbids.
func unevidenced(f Finding) bool {
	if f.Status != Pass || len(f.Evidence) > 0 {
		return false
	}
	_, derived := derivedBasis(f.ID)
	return !derived
}

// enforceEvidence records a pass that has no evidence, and is not a
// derived check, as info (ADR-0002; see evidence.go).
func enforceEvidence(f Finding) Finding {
	if !unevidenced(f) {
		return f
	}
	f.Status, f.Detail = Info, f.Detail+unevidencedNote
	if onUnevidenced != nil {
		onUnevidenced(f)
	}
	return f
}

// unevidencedNote is appended to the detail of a pass recorded as info.
const unevidencedNote = " (recorded as info: the check made no request and cited no evidence, ADR-0002)"

// onUnevidenced, when set, is told about every pass check.done recorded
// as info for want of evidence. The test suite sets it and fails if any
// check does this, which is how a new check that forgets its evidence is
// caught before it ships as an info nobody meant.
var onUnevidenced func(Finding)
