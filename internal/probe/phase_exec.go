// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"satellion.com/passmcp"
	"satellion.com/passmcp/diagnostics"
	"satellion.com/passmcp/internal/telemetry"
	"satellion.com/passmcp/transport"
)

// ToolResult records one synthetic tool invocation.
type ToolResult struct {
	Name         string         `json:"name"`
	Executed     bool           `json:"executed"`
	SkipReason   string         `json:"skip_reason,omitempty"`
	Arguments    map[string]any `json:"arguments,omitempty"`
	ArgsSource   string         `json:"args_source,omitempty"`
	Duration     Millis         `json:"duration_ms,omitempty"`
	OK           bool           `json:"ok"`
	ToolError    string         `json:"tool_error,omitempty"`
	ProtoError   string         `json:"protocol_error,omitempty"`
	ContentTypes []string       `json:"content_types,omitempty"`
	TextBytes    int            `json:"text_bytes,omitempty"`
	Structured   bool           `json:"structured_content"`
	SchemaIssues []string       `json:"schema_issues,omitempty"`
	// NegativeTest is what happened when a required argument was omitted.
	NegativeTest string `json:"negative_test,omitempty"`
	// NeedsInput lists the client-side methods the server asked for before
	// it would finish the call — elicitation/create, sampling/createMessage.
	//
	// A distinct outcome from OK, ToolError and ProtoError, because it is
	// none of them: the server behaved correctly and the call did not
	// complete. passmcp has no user to elicit from and no model to sample, so
	// it reports the request rather than answering it.
	NeedsInput []string `json:"needs_input,omitempty"`
}

// ResourceResult records one resources/read.
type ResourceResult struct {
	URI      string `json:"uri"`
	Duration Millis `json:"duration_ms"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Bytes    int    `json:"bytes,omitempty"`
	MimeType string `json:"mime_type,omitempty"`
	Items    int    `json:"items,omitempty"`
}

// PromptResult records one prompts/get.
type PromptResult struct {
	Name     string `json:"name"`
	Duration Millis `json:"duration_ms"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Messages int    `json:"messages,omitempty"`
}

// phaseExecution invokes what the policy allows and validates content.
func phaseExecution(ctx context.Context, s *Session) []Finding {
	var out []Finding
	e := &execRun{
		ctx:     ctx,
		s:       s,
		limiter: diagnostics.NewLimiter(s.Opts.RPS, 1),
		gen:     diagnostics.NewGenerator(s.Opts.Seed),
	}
	e.gen.FillOptional = s.Opts.FillOptional

	out = append(out, s.check("execution.policy", "Safety policy").info(policyDescribe(s.Opts.Policy)))

	var n toolTally
	for _, t := range s.Tools {
		tr, aborted := e.runTool(t, &n)
		if aborted {
			return out
		}
		s.ToolResults = append(s.ToolResults, tr)
	}

	out = append(out, toolsFinding(s, n))
	if n.executed > 0 {
		out = append(out, executedFindings(s, n)...)
	}

	// ---- resources ----
	f, aborted := e.readResources()
	if aborted {
		return out
	}
	out = append(out, f...)

	// ---- prompts ----
	f, aborted = e.getPrompts()
	if aborted {
		return out
	}
	out = append(out, f...)

	// A protocol.* finding emitted from the execution phase, because the
	// observations it judges only exist once tools have been called. The
	// same shape as protocol.routing_headers, which the handshake phase
	// emits for the same reason: the id names the mechanism and the phase
	// names when it could be measured.
	out = append(out, checkMRTR(s))
	// The Tasks extension, for the same reason: following a task needs a
	// tool the execution phase has already called.
	out = append(out, checkTasks(ctx, s)...)
	return out
}

// execRun is the state one execution phase shares across its calls: the
// session, the rate limiter every request waits on, and the argument
// generator.
type execRun struct {
	ctx     context.Context
	s       *Session
	limiter *diagnostics.Limiter
	gen     *diagnostics.Generator
}

// pctx labels a request as part of the execution phase.
func (e *execRun) pctx(label string) context.Context {
	return telemetry.WithPhase(e.ctx, "execution", label)
}

// toolTally counts the outcomes of the tool invocations.
type toolTally struct {
	executed, okCount, toolErr, protoErr, schemaBad, negWeak, needsInput int
}

// runTool decides whether one tool may run, invokes it, and records the
// outcome. aborted reports that the context ended while waiting for the
// limiter, in which case the result is discarded.
func (e *execRun) runTool(t passmcp.Tool, n *toolTally) (tr ToolResult, aborted bool) {
	s := e.s
	tr = ToolResult{Name: t.Name}
	d := s.Opts.Policy.Decide(t)
	if !d.Execute {
		tr.SkipReason = d.Reason
		return tr, false
	}
	if ov, ok := s.Opts.ToolArgs[t.Name]; ok {
		tr.Arguments, tr.ArgsSource = ov, "override"
	} else {
		args, err := e.gen.Arguments(t.InputSchema)
		if err != nil {
			tr.SkipReason = "inputSchema unparsable: " + err.Error()
			return tr, false
		}
		tr.Arguments, tr.ArgsSource = args, "generated"
	}
	tr.Executed = true
	n.executed++
	if err := e.limiter.Wait(e.ctx); err != nil {
		return tr, true
	}
	cctx, cancel := context.WithTimeout(e.pctx("tools/call "+t.Name), s.Opts.CallTimeout)
	start := time.Now()
	from := s.Opts.Recorder.Count()
	res, err := s.Client.CallTool(cctx, t.Name, tr.Arguments)
	tr.Duration = Millis(time.Since(start))
	cancel()
	e.classifyCall(t, &tr, res, err, n)
	if tr.OK {
		s.noteOutput(t.Name, res, reqRef(from, s.Opts.Recorder.Count()))
	}
	// Negative test: omit a required argument and expect rejection.
	if req := requiredArgs(t.InputSchema); len(req) > 0 && tr.ArgsSource != "override" {
		if err := e.limiter.Wait(e.ctx); err != nil {
			return tr, true
		}
		e.negativeTest(t, &tr, req[0], n)
	}
	return tr, false
}

// classifyCall files one tools/call outcome under exactly one of: needing
// client input, a protocol error, a tool error, or a success.
func (e *execRun) classifyCall(t passmcp.Tool, tr *ToolResult, res *passmcp.CallToolResult, err error, n *toolTally) {
	s := e.s
	switch ir, wantsInput := asInputRequired(err); {
	case wantsInput:
		// Not a protocol error. The 2026-07-28 revision replaced
		// server-initiated sampling and elicitation with this: the
		// server answers input_required, and the client retries the
		// call with the answers attached. A tool that does it is
		// implementing the current revision correctly, and counting it
		// as a protocol failure told a conformant server it was broken
		// — the same mistake the ping check made once.
		n.needsInput++
		tr.NeedsInput = requestedMethods(ir)
		s.MRTR = append(s.MRTR, observe("tools/call "+t.Name, ir))
	case err != nil:
		n.protoErr++
		tr.ProtoError = err.Error()
		if errors.Is(err, context.DeadlineExceeded) {
			tr.ProtoError = "timeout after " + s.Opts.CallTimeout.String()
		}
	case res.IsError:
		n.toolErr++
		tr.ToolError = truncate(res.Text(), 200)
	default:
		n.okCount++
		tr.OK = true
		recordContent(t, tr, res)
		if len(tr.SchemaIssues) > 0 {
			n.schemaBad++
		}
	}
}

// recordContent notes what a successful call returned and whether it
// honoured the tool's outputSchema.
func recordContent(t passmcp.Tool, tr *ToolResult, res *passmcp.CallToolResult) {
	seen := map[string]bool{}
	for _, c := range res.Content {
		if !seen[c.Type] {
			seen[c.Type] = true
			tr.ContentTypes = append(tr.ContentTypes, c.Type)
		}
		tr.TextBytes += len(c.Text)
	}
	tr.Structured = len(res.StructuredContent) > 0
	if len(res.Content) == 0 && !tr.Structured {
		tr.SchemaIssues = append(tr.SchemaIssues, "empty result: no content and no structuredContent")
	}
	if len(t.OutputSchema) > 0 {
		if !tr.Structured {
			tr.SchemaIssues = append(tr.SchemaIssues, "outputSchema declared but structuredContent missing")
		} else {
			tr.SchemaIssues = append(tr.SchemaIssues, diagnostics.Validate(t.OutputSchema, res.StructuredContent)...)
		}
	}
}

// negativeTest calls the tool again without its first required argument
// and records whether the server rejected the call.
func (e *execRun) negativeTest(t passmcp.Tool, tr *ToolResult, missing string, n *toolTally) {
	s := e.s
	cctx, cancel := context.WithTimeout(e.pctx("tools/call "+t.Name+" (missing "+missing+")"), s.Opts.CallTimeout)
	bad := map[string]any{}
	for k, v := range tr.Arguments {
		if k != missing {
			bad[k] = v
		}
	}
	res, err := s.Client.CallTool(cctx, t.Name, bad)
	cancel()
	var rpc *transport.RPCError
	switch {
	case err != nil && asRPC(err, &rpc):
		tr.NegativeTest = fmt.Sprintf("rejected (JSON-RPC %d)", rpc.Code)
	case err != nil:
		tr.NegativeTest = "transport error: " + truncate(err.Error(), 80)
	case res.IsError:
		tr.NegativeTest = "rejected (isError)"
	default:
		tr.NegativeTest = "ACCEPTED without required " + missing
		n.negWeak++
	}
}

// toolsFinding is the execution.tools verdict on the invocations as a whole.
func toolsFinding(s *Session, n toolTally) Finding {
	c := s.check("execution.tools", "Tool invocations")
	switch {
	case len(s.Tools) == 0:
		return c.skip("no tools")
	case n.executed == 0:
		return c.warn(fmt.Sprintf("0 of %d tools executed: none permitted by policy", len(s.Tools)), "annotate read-only tools with readOnlyHint, or opt in with --allow-mutations")
	}
	detail := fmt.Sprintf("%d executed: %d ok, %d tool errors, %d protocol errors", n.executed, n.okCount, n.toolErr, n.protoErr)
	if n.needsInput > 0 {
		detail += fmt.Sprintf(", %d needing client input", n.needsInput)
	}
	switch {
	case n.protoErr > 0:
		return c.fail(Major, detail, "protocol errors and timeouts mean the call never completed")
	case n.needsInput == n.executed:
		// Every tool asked for input, so none was exercised. That is a
		// fact about what a diagnostic can reach, not a defect: there
		// is no user here to elicit from and no model to sample.
		return c.info(detail + " (every call asked for client input before finishing, which passmcp reports rather than answers; protocol.mrtr judges the requests)")
	case n.needsInput > 0:
		return c.info(detail + " (the calls needing input were not exercised further)")
	case n.toolErr == n.executed:
		return c.warn(detail+" (every call returned isError; generated arguments may not suit this server, use --arg to supply real ones)", "")
	case n.toolErr > 0:
		return c.info(detail + " (isError results are often correct rejections of generated arguments)")
	default:
		return c.pass(detail)
	}
}

// executedFindings are the verdicts that need at least one call to have
// run: the output contract, argument validation, error guidance and
// payload size.
func executedFindings(s *Session, n toolTally) []Finding {
	var out []Finding
	c := s.check("execution.content", "Results validate against outputSchema")
	if n.schemaBad > 0 {
		out = append(out, c.fail(Major, fmt.Sprintf("%d tool(s) returned content that does not match their contract", n.schemaBad), "see per-tool schema issues"))
	} else {
		out = append(out, c.pass("no contract violations among successful calls"))
	}
	c = s.check("execution.validation", "Tools reject missing required arguments")
	if n.negWeak > 0 {
		out = append(out, c.fail(Minor, fmt.Sprintf("%d tool(s) accepted a call with a required argument omitted", n.negWeak), "validate arguments against inputSchema before executing"))
	} else {
		out = append(out, c.pass("all tested tools rejected the call"))
	}
	// A rejection is correct behaviour; what it said is a separate
	// property, and the rejections are already in hand.
	out = append(out, checkErrorGuidance(s))

	// And what the answers cost the caller, which the run already
	// counted.
	out = append(out, checkPayloadSize(s)...)
	// And what the answers said to the model rather than to the caller.
	out = append(out, checkOutputInjection(s))
	return out
}

// readTally counts the outcomes of resource reads or prompt renders.
type readTally struct{ ok, failed, empty int }

// readResources reads up to MaxResources of the listed resources and
// judges the reads. aborted reports that the context ended mid-way.
func (e *execRun) readResources() (out []Finding, aborted bool) {
	s := e.s
	n := len(s.Resources)
	if n == 0 {
		return nil, false
	}
	limit := min(n, s.Opts.MaxResources)
	var t readTally
	for _, r := range s.Resources[:limit] {
		if err := e.limiter.Wait(e.ctx); err != nil {
			return nil, true
		}
		s.ResourceResults = append(s.ResourceResults, e.readResource(r, &t))
	}
	c := s.check("execution.resources", "Resource reads")
	detail := fmt.Sprintf("%d of %d read: %d ok, %d failed, %d empty", limit, n, t.ok, t.failed, t.empty)
	switch {
	case t.failed > 0:
		return []Finding{c.fail(Major, detail, "every listed resource should be readable")}, false
	case t.empty > 0:
		return []Finding{c.warn(detail, "a read that returns no contents is indistinguishable from a broken one")}, false
	default:
		return []Finding{c.pass(detail)}, false
	}
}

// readResource performs one resources/read and records what came back.
func (e *execRun) readResource(r passmcp.Resource, t *readTally) ResourceResult {
	s := e.s
	rr := ResourceResult{URI: r.URI}
	cctx, cancel := context.WithTimeout(e.pctx("resources/read"), s.Opts.CallTimeout)
	start := time.Now()
	res, err := s.Client.ReadResource(cctx, r.URI)
	rr.Duration = Millis(time.Since(start))
	cancel()
	if err != nil {
		t.failed++
		rr.Error = truncate(err.Error(), 120)
		return rr
	}
	t.ok++
	rr.OK = true
	rr.Items = len(res.Contents)
	for _, c := range res.Contents {
		rr.Bytes += len(c.Text) + len(c.Blob)
		if rr.MimeType == "" {
			rr.MimeType = c.MimeType
		}
	}
	if rr.Items == 0 {
		t.empty++
	}
	return rr
}

// getPrompts renders up to MaxPrompts of the listed prompts and judges
// the renders. aborted reports that the context ended mid-way.
func (e *execRun) getPrompts() (out []Finding, aborted bool) {
	s := e.s
	n := len(s.Prompts)
	if n == 0 {
		return nil, false
	}
	limit := min(n, s.Opts.MaxPrompts)
	var t readTally
	for _, p := range s.Prompts[:limit] {
		if err := e.limiter.Wait(e.ctx); err != nil {
			return nil, true
		}
		s.PromptResults = append(s.PromptResults, e.getPrompt(p, &t))
	}
	c := s.check("execution.prompts", "Prompt rendering")
	detail := fmt.Sprintf("%d of %d rendered: %d ok, %d failed, %d empty", limit, n, t.ok, t.failed, t.empty)
	switch {
	case t.failed > 0:
		return []Finding{c.fail(Major, detail, "prompts/get should succeed with the required arguments")}, false
	case t.empty > 0:
		return []Finding{c.warn(detail, "a prompt with no messages is unusable")}, false
	default:
		return []Finding{c.pass(detail)}, false
	}
}

// getPrompt performs one prompts/get with every required argument set to
// a placeholder, and records what came back.
func (e *execRun) getPrompt(p passmcp.Prompt, t *readTally) PromptResult {
	s := e.s
	args := map[string]string{}
	for _, a := range p.Arguments {
		if a.Required {
			args[a.Name] = "example"
		}
	}
	pr := PromptResult{Name: p.Name}
	cctx, cancel := context.WithTimeout(e.pctx("prompts/get "+p.Name), s.Opts.CallTimeout)
	start := time.Now()
	res, err := s.Client.GetPrompt(cctx, p.Name, args)
	pr.Duration = Millis(time.Since(start))
	cancel()
	if err != nil {
		t.failed++
		pr.Error = truncate(err.Error(), 120)
		return pr
	}
	t.ok++
	pr.OK = true
	pr.Messages = len(res.Messages)
	if pr.Messages == 0 {
		t.empty++
	}
	return pr
}

func policyDescribe(p diagnostics.Policy) string {
	parts := []string{"read-only tools"}
	if p.AllowDestructive {
		parts = []string{"ALL tools including destructive"}
	} else if p.AllowMutations {
		parts = append(parts, "non-destructive mutations")
	}
	s := strings.Join(parts, " + ")
	if len(p.Only) > 0 {
		s += "; only " + strings.Join(p.Only, ",")
	}
	if len(p.Deny) > 0 {
		s += "; deny " + strings.Join(p.Deny, ",")
	}
	return s
}

func requiredArgs(schema json.RawMessage) []string {
	var s struct {
		Required []string `json:"required"`
	}
	_ = json.Unmarshal(schema, &s)
	return s.Required
}
