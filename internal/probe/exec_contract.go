// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"fmt"

	"satellion.com/passmcp"
	"satellion.com/passmcp/transport"
)

// uriRead is one resources/read that returned contents: the URI asked
// for, the URIs the contents came back under, and the requests it took.
type uriRead struct {
	requested string
	got       []string
	from, to  int
}

// noteURIs records the URIs a read's contents were filed under. A read
// with no contents is not recorded: there is nothing to compare, and
// execution.resources already reports it.
func (e *execRun) noteURIs(requested string, contents []passmcp.ResourceContents, from, to int) {
	if len(contents) == 0 {
		return
	}
	r := uriRead{requested: requested, from: from, to: to}
	for _, c := range contents {
		r.got = append(r.got, c.URI)
	}
	e.uriReads = append(e.uriReads, r)
}

// mismatch describes how a read's contents disagree with the URI asked
// for, or returns "" when one of them is filed under it.
//
// A read may return more than one item — a directory-like resource
// answers with its children — so the rule is that the resource asked for
// is among them, not that every item repeats its URI. An item with no uri
// at all is wrong either way: the field is required.
func (r uriRead) mismatch() string {
	found := false
	for i, u := range r.got {
		if u == "" {
			return fmt.Sprintf("%s returned contents[%d] with no uri", truncate(r.requested, 80), i)
		}
		found = found || u == r.requested
	}
	if found {
		return ""
	}
	return fmt.Sprintf("%s returned %s", truncate(r.requested, 80), truncate(r.got[0], 80))
}

// resourceURIFinding judges whether each read's contents came back under
// the URI requested, citing the reads that showed it.
func (e *execRun) resourceURIFinding() Finding {
	s := e.s
	c := s.check("execution.resources.uri", "Resource reads return the URI requested")
	if len(e.uriReads) == 0 {
		return c.skip("no resource read returned contents to compare")
	}
	var bad []string
	for _, r := range e.uriReads {
		if m := r.mismatch(); m != "" {
			bad = append(bad, m)
			c.ev(reqRef(r.from, r.to))
		}
	}
	if len(bad) > 0 {
		// The URIs are the server's text.
		return c.warn(s.Opts.Recorder.Redactor.String(summariseIssues(bad)),
			"file each read's contents under the uri the client asked for: a client holding several resources matches contents to requests by that field")
	}
	last := e.uriReads[len(e.uriReads)-1]
	c.ev(reqRef(e.uriReads[0].from, last.to))
	return c.pass(fmt.Sprintf("%s returned contents under the URI requested", plural(len(e.uriReads), "read")))
}

// refusal is how a server answered a prompts/get missing a required
// argument.
type refusal int

const (
	// refusedInvalidParams is the answer the specification names: -32602.
	refusedInvalidParams refusal = iota
	// refusedOtherwise is a refusal a client cannot classify: another
	// JSON-RPC code, or no JSON-RPC answer at all.
	refusedOtherwise
	// renderedAnyway is the defect: the prompt rendered without it.
	renderedAnyway
)

// promptNegative is one prompts/get made without a required argument.
type promptNegative struct {
	prompt, missing, outcome string
	answer                   refusal
	ref                      string
}

// promptNegatives are the negative renders one execution phase made, and
// how many prompts declared a required argument at all.
type promptNegatives struct {
	declared int
	runs     []promptNegative
}

// firstRequiredArg names a prompt's first required argument, or "".
func firstRequiredArg(p passmcp.Prompt) string {
	for _, a := range p.Arguments {
		if a.Required {
			return a.Name
		}
	}
	return ""
}

// negativeRender renders p again without its first required argument,
// when it has one and rendered with it: a server that refused the full
// call too would say nothing about the missing argument by refusing this
// one. aborted reports that the context ended while waiting.
func (e *execRun) negativeRender(p passmcp.Prompt, pr *PromptResult, neg *promptNegatives) (aborted bool) {
	missing := firstRequiredArg(p)
	if missing == "" {
		return false
	}
	neg.declared++
	if !pr.OK {
		return false
	}
	if err := e.limiter.Wait(e.ctx); err != nil {
		return true
	}
	neg.runs = append(neg.runs, e.promptNegativeTest(p, pr, missing))
	return false
}

// promptNegativeTest performs one prompts/get with every required
// argument but missing, and records how the server answered.
func (e *execRun) promptNegativeTest(p passmcp.Prompt, pr *PromptResult, missing string) promptNegative {
	s := e.s
	args := map[string]string{}
	for _, a := range p.Arguments {
		if a.Required && a.Name != missing {
			args[a.Name] = "example"
		}
	}
	cctx, cancel := context.WithTimeout(e.pctx("prompts/get "+p.Name+" (missing "+missing+")"), s.Opts.CallTimeout)
	from := s.Opts.Recorder.Count()
	_, err := s.Client.GetPrompt(cctx, p.Name, args)
	cancel()
	n := promptNegative{prompt: p.Name, missing: missing, ref: reqRef(from, s.Opts.Recorder.Count())}
	n.answer, n.outcome = classifyRefusal(err, missing)
	pr.NegativeTest = n.outcome
	return n
}

// classifyRefusal names how a call missing a required argument was
// answered, in the words ToolResult.NegativeTest uses.
func classifyRefusal(err error, missing string) (refusal, string) {
	var rpc *transport.RPCError
	switch {
	case err == nil:
		return renderedAnyway, "ACCEPTED without required " + missing
	case asRPC(err, &rpc) && rpc.Code == -32602:
		return refusedInvalidParams, "rejected (JSON-RPC -32602)"
	case rpc != nil:
		return refusedOtherwise, fmt.Sprintf("rejected (JSON-RPC %d)", rpc.Code)
	default:
		return refusedOtherwise, "transport error: " + truncate(err.Error(), 80)
	}
}

// promptValidationFinding judges the negative renders, citing the
// requests that showed each outcome.
func promptValidationFinding(s *Session, neg promptNegatives, rendered int) Finding {
	c := s.check("execution.prompts.validation", "Prompts reject a missing required argument")
	switch {
	case neg.declared == 0:
		return c.skip(fmt.Sprintf("no prompt among the %d rendered declares a required argument", rendered))
	case len(neg.runs) == 0:
		return c.skip("no prompt with a required argument rendered with it, so a refusal without it would show nothing")
	}
	var accepted, other []string
	for _, n := range neg.runs {
		switch n.answer {
		case renderedAnyway:
			accepted = append(accepted, fmt.Sprintf("%s (missing %s)", truncate(n.prompt, 64), n.missing))
			c.ev(n.ref)
		case refusedOtherwise:
			other = append(other, fmt.Sprintf("%s (missing %s): %s", truncate(n.prompt, 64), n.missing, n.outcome))
			c.ev(n.ref)
		}
	}
	return promptValidationVerdict(s, c, neg.runs, accepted, other)
}

// promptValidationVerdict closes execution.prompts.validation: a render
// without a required argument fails, a refusal with the wrong code warns.
func promptValidationVerdict(s *Session, c *check, runs []promptNegative, accepted, other []string) Finding {
	// Prompt and argument names, and error text, are the server's.
	red := s.Opts.Recorder.Redactor.String
	switch {
	case len(accepted) > 0:
		return c.fail(Minor, red(fmt.Sprintf("%d of %d rendered without a required argument: %s", len(accepted), len(runs), summariseIssues(accepted))),
			"check prompts/get arguments against the prompt's declared arguments and refuse a missing required one with JSON-RPC -32602")
	case len(other) > 0:
		return c.warn(red(summariseIssues(other)),
			"refuse a missing required argument with JSON-RPC -32602 (invalid params), which is what the specification names and what a client can act on")
	}
	for _, n := range runs {
		c.ev(n.ref)
	}
	return c.pass(fmt.Sprintf("%s refused a render without a required argument with -32602", plural(len(runs), "prompt")))
}
