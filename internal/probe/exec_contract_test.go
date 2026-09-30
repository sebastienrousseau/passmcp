// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"testing"

	"satellion.com/passmcp/internal/creds"
)

// throughExecution runs every phase up to execution against f.
func throughExecution(t *testing.T, f *fakeServer) map[string]Finding {
	t.Helper()
	f.acceptAnyToken = true
	_, fs := run(t, f, &creds.Credentials{Mode: creds.ModeBearer, Token: "tok-1234"}, func(o *Options) {
		o.Only = []string{"net", "discovery", "auth", "handshake", "catalog", "execution"}
	})
	return fs
}

func TestResourceReadURI(t *testing.T) {
	// The fake answers under the URI it was asked for, and the pass cites
	// the read.
	fs := throughExecution(t, newFakeServer(t))
	expect(t, fs, "execution.resources.uri", Pass, "1 read")
	if len(fs["execution.resources.uri"].Evidence) == 0 {
		t.Error("a pass must cite the read it came from")
	}

	// Contents filed under another URI warn, naming both and citing the
	// read that showed it.
	f := newFakeServer(t)
	f.q.readURI = "fake://doc/other"
	fs = throughExecution(t, f)
	expect(t, fs, "execution.resources.uri", Warn, "fake://doc/1 returned fake://doc/other")
	if len(fs["execution.resources.uri"].Evidence) == 0 {
		t.Error("the warning must cite the read")
	}

	// Contents with no uri at all.
	f = newFakeServer(t)
	f.q.readURI = "-"
	expect(t, throughExecution(t, f), "execution.resources.uri", Warn, "no uri")

	// Nothing came back to compare.
	f = newFakeServer(t)
	f.q.readFail = true
	expect(t, throughExecution(t, f), "execution.resources.uri", Skip, "no resource read returned contents")
	f = newFakeServer(t)
	f.q.resourcesEmpty = true
	expect(t, throughExecution(t, f), "execution.resources.uri", Skip, "no resource read returned contents")
}

func TestPromptValidation(t *testing.T) {
	// The fake refuses a render without its required argument with
	// -32602, and the pass cites the request that showed it.
	f := newFakeServer(t)
	f.acceptAnyToken = true
	s, fs := run(t, f, &creds.Credentials{Mode: creds.ModeBearer, Token: "tok-1234"}, func(o *Options) {
		o.Only = []string{"net", "discovery", "auth", "handshake", "catalog", "execution"}
	})
	expect(t, fs, "execution.prompts.validation", Pass, "1 prompt")
	expect(t, fs, "execution.prompts", Pass, "1 ok")
	if len(fs["execution.prompts.validation"].Evidence) == 0 {
		t.Error("a pass must cite the request that showed it")
	}
	if len(s.PromptResults) != 1 || s.PromptResults[0].NegativeTest != "rejected (JSON-RPC -32602)" {
		t.Errorf("prompt results = %+v", s.PromptResults)
	}

	// Rendering anyway is the defect.
	f = newFakeServer(t)
	f.q.promptLenient = true
	fs = throughExecution(t, f)
	expect(t, fs, "execution.prompts.validation", Fail, "summarise (missing doc)")
	if got := fs["execution.prompts.validation"]; got.Severity != Minor || len(got.Evidence) == 0 {
		t.Errorf("want a cited minor failure: %+v", got)
	}

	// A refusal with another code is a refusal a client cannot classify.
	f = newFakeServer(t)
	f.q.promptMissingCode = -32603
	expect(t, throughExecution(t, f), "execution.prompts.validation", Warn, "JSON-RPC -32603")

	// A refusal that is not JSON-RPC at all.
	f = newFakeServer(t)
	f.q.promptMissingCode = 500
	expect(t, throughExecution(t, f), "execution.prompts.validation", Warn, "HTTP status 500")

	// A server that refuses the full render too says nothing about the
	// missing argument by refusing this one, so no request is made.
	f = newFakeServer(t)
	f.q.promptsFail = true
	f.acceptAnyToken = true
	s, fs = run(t, f, &creds.Credentials{Mode: creds.ModeBearer, Token: "tok-1234"}, func(o *Options) {
		o.Only = []string{"net", "discovery", "auth", "handshake", "catalog", "execution"}
	})
	expect(t, fs, "execution.prompts.validation", Skip, "rendered with it")
	if s.PromptResults[0].NegativeTest != "" {
		t.Errorf("no negative render expected: %+v", s.PromptResults[0])
	}

	// Nothing required, nothing to omit.
	f = newFakeServer(t)
	f.q.promptOptional = true
	expect(t, throughExecution(t, f), "execution.prompts.validation", Skip, "declares a required argument")
}
