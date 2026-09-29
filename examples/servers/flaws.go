// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package main

// Flaw is one deliberate defect the demonstration server can carry, and the
// check that catches it. The table is the single source of truth: `-list`
// prints it, and servers_test.go runs passmcp against every row and fails
// when the named check does not report the named status.
type Flaw struct {
	// Name is the value -flaw takes.
	Name string
	// Check is the passmcp check id that catches it, empty for the
	// baseline.
	Check string
	// Status is what that check reports: fail for a protocol violation,
	// warn for a risk the specification permits.
	Status string
	// What says in one sentence what the server does wrong.
	What string
}

// Baseline is the server with no deliberate defect.
const Baseline = "baseline"

// Flaws is the catalogue, the baseline first.
var Flaws = []Flaw{
	{Baseline, "", "", "No deliberate flaw: every other server is this one plus one defect. It still draws the two warnings listed below."},
	{"wrong-id", "protocol.id_echo", "fail",
		"Answers every request with an id the client never sent, so no client can match a response to its request."},
	{"accepts-malformed-json", "protocol.malformed_json", "fail",
		"Answers a truncated JSON body with 200 instead of a -32700 parse error."},
	{"any-origin", "protocol.origin", "fail",
		"Accepts a request from any browser Origin, the opening a DNS-rebinding page needs to reach a local server."},
	{"instructs-the-model", "execution.output_injection", "warn",
		"A read-only tool whose result tells the model what to do next instead of returning data."},
	{"toxic-pair", "catalog.toxic_combination", "warn",
		"Exposes a tool that reads the user's inbox beside one that sends email: everything a prompt injection needs to exfiltrate."},
	{"unbounded-result", "execution.payload_size", "warn",
		"A read-only tool that returns 1 MiB of text with no pagination or truncation, filling the caller's context window."},
	{"lying-output-schema", "execution.content", "fail",
		"Declares an outputSchema and then returns structured content that does not satisfy it."},
}

// BaselineWarning is a warning the baseline draws on purpose, and why it is
// left in rather than engineered away.
type BaselineWarning struct {
	Check, Why string
}

// BaselineWarnings are the only findings worse than info the baseline
// produces. Every flawed server produces these plus its own check.
var BaselineWarnings = []BaselineWarning{
	{"auth.unauthenticated_tools", "a demonstration on loopback has no authorization server to send you to"},
	{"handshake.protocol_era", "it speaks the 2025-11-25 handshake (initialize, Mcp-Session-Id), which most servers in use still do"},
}

// lookup returns the flaw called name.
func lookup(name string) (Flaw, bool) {
	for _, f := range Flaws {
		if f.Name == name {
			return f, true
		}
	}
	return Flaw{}, false
}
