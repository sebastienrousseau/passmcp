// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"satellion.com/passmcp/internal/telemetry"
	"satellion.com/passmcp/transport"
)

// The Tasks extension (io.modelcontextprotocol/tasks) lets a server answer a
// tools/call with a durable handle instead of a result, which the client
// polls with tasks/get until the task reaches a terminal state. A server that
// implements it wrongly does not fail loudly: a task that never resolves, a
// handle that cannot be retrieved, or a "completed" task with no result all
// look, to an agent, like a call that hangs.
//
// Everything here stays inside what passmcp already does. The task passmcp
// follows is created by calling a read-only tool the execution phase already
// called with the same arguments; the requests that probe refusals name a
// task id that cannot exist; and a task passmcp started and did not see
// finish is cancelled, not left running. Nothing here is adversarial
// (ADR 0008).
//
// These are protocol.* findings emitted from the execution phase, like
// protocol.mrtr: the lifecycle needs a tool, and tools are only known once
// the catalogue has been read and called.

const tasksExtension = "io.modelcontextprotocol/tasks"

// taskPollBudget bounds how long a task is followed. A variable so a test
// can shorten it; a real run should not wait longer on one task.
var taskPollBudget = 30 * time.Second

// Poll interval bounds. The server's pollIntervalMs is honoured inside them:
// faster would be the abusive client passmcp tells servers to rate-limit, and
// slower than five seconds spends the budget on waiting.
const (
	taskPollMin     = 250 * time.Millisecond
	taskPollMax     = 5 * time.Second
	taskPollDefault = time.Second
)

// Each check is created at a literal call site, because the published
// inventory is generated from (*Session).check calls and an id built from a
// table would be invisible to it.
func taskUnknownIDCheck(s *Session) *check {
	return s.check("protocol.tasks.unknown_id", "An unknown task id is refused")
}

func taskCapabilityCheck(s *Session) *check {
	return s.check("protocol.tasks.capability", "Task methods require the declared capability")
}

func taskUndeclaredCheck(s *Session) *check {
	return s.check("protocol.tasks.undeclared", "No task is returned to a client that did not ask for one")
}

func taskLifecycleCheck(s *Session) *check {
	return s.check("protocol.tasks.lifecycle", "A task reaches a terminal state and keeps it")
}

// taskChecks are the four, in report order.
var taskChecks = []func(*Session) *check{taskUnknownIDCheck, taskCapabilityCheck, taskUndeclaredCheck, taskLifecycleCheck}

// taskTerminal are the states a task cannot leave.
var taskTerminal = map[string]bool{"completed": true, "failed": true, "cancelled": true}

var taskStatuses = map[string]bool{"working": true, "input_required": true, "completed": true, "failed": true, "cancelled": true}

// checkTasks runs the four Tasks checks, or names why they cannot run.
func checkTasks(ctx context.Context, s *Session) []Finding {
	skipAll := func(reason string) []Finding {
		out := make([]Finding, 0, len(taskChecks))
		for _, mk := range taskChecks {
			out = append(out, mk(s).skip(reason))
		}
		return out
	}
	if !s.Stateless() {
		return skipAll("the Tasks extension is defined for the " + transport.V20260728 +
			" revision; the tasks built into 2025-11-25 are a different mechanism and are not checked")
	}
	if s.Era == nil || !slices.Contains(s.Era.Discovered.ExtensionIDs(), tasksExtension) {
		return skipAll("the server does not advertise " + tasksExtension + " in capabilities.extensions")
	}

	unknown := "passmcp-unknown-task-" + shortTrace(s)
	out := []Finding{
		checkTaskUnknownID(ctx, s, unknown),
		checkTaskCapability(ctx, s, unknown),
	}

	tool, ok := taskTool(s)
	if !ok {
		reason := "no read-only tool completed in the execution phase, so there is nothing passmcp may call again to ask for a task"
		out = append(out, taskUndeclaredCheck(s).skip(reason), taskLifecycleCheck(s).skip(reason))
		return out
	}
	out = append(out, checkTaskUndeclared(ctx, s, tool), checkTaskLifecycle(ctx, s, tool))
	return out
}

// taskTool picks a tool the execution phase called successfully: one the
// safety policy already permitted, with arguments that already worked.
func taskTool(s *Session) (ToolResult, bool) {
	for _, r := range s.ToolResults {
		if r.Executed && r.OK {
			return r, true
		}
	}
	return ToolResult{}, false
}

func shortTrace(s *Session) string {
	if len(s.TraceID) >= 8 {
		return s.TraceID[:8]
	}
	return s.TraceID
}

// taskCall sends one raw request, declaring the Tasks extension on it when
// declare is true. Capabilities are per request on this revision, so the
// declaration applies to this call and no other.
func (s *Session) taskCall(ctx context.Context, label, method string, params map[string]any, declare bool) (*transport.Response, error) {
	if declare {
		params["_meta"] = map[string]any{
			transport.MetaClientCapabilities: map[string]any{
				"extensions": map[string]any{tasksExtension: map[string]any{}},
			},
		}
	}
	body, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	id := s.nextID()
	rctx, cancel := s.stdioDeadline(telemetry.WithPhase(ctx, "execution", label))
	defer cancel()
	rep, err := s.rawExchange(rctx, rawSend{Request: &transport.Request{
		JSONRPC: "2.0", ID: &id, Method: method, Params: body,
	}})
	if err != nil {
		return nil, err
	}
	if rep.Response == nil {
		return nil, fmt.Errorf("no JSON-RPC response (HTTP %d)", rep.Status)
	}
	return rep.Response, nil
}

func checkTaskUnknownID(ctx context.Context, s *Session, unknown string) Finding {
	c := taskUnknownIDCheck(s)
	resp, err := s.taskCall(ctx, "tasks/get unknown", "tasks/get", map[string]any{"taskId": unknown}, true)
	switch {
	case err != nil:
		return c.info("request failed: " + truncate(err.Error(), 100))
	case resp.Error != nil && resp.Error.Code == -32602:
		return c.pass("-32602 for a task id that was never issued")
	case resp.Error != nil:
		return c.warn(fmt.Sprintf("answered a task id that was never issued with error %d", resp.Error.Code),
			"return -32602 (Invalid params) for an unknown or expired task id, as the extension requires; a client uses the code to stop polling a task that no longer exists")
	default:
		return c.fail(Major, "answered tasks/get for a task id that was never issued as if it existed",
			"return -32602 for an unknown task id. A client polling a mistyped or expired id has to be told it does not exist, or it polls forever")
	}
}

func checkTaskCapability(ctx context.Context, s *Session, unknown string) Finding {
	c := taskCapabilityCheck(s)
	resp, err := s.taskCall(ctx, "tasks/get undeclared", "tasks/get", map[string]any{"taskId": unknown}, false)
	switch {
	case err != nil:
		return c.info("request failed: " + truncate(err.Error(), 100))
	case resp.Error != nil && resp.Error.Code == transport.CodeMissingClientCapability:
		return c.pass(fmt.Sprintf("%d for a client that did not declare %s", transport.CodeMissingClientCapability, tasksExtension))
	case resp.Error != nil:
		return c.warn(fmt.Sprintf("answered tasks/get from a client that did not declare the extension with error %d, not %d",
			resp.Error.Code, transport.CodeMissingClientCapability),
			fmt.Sprintf("check the capability before the task id and return %d (Missing Required Client Capability) naming %s, so a client knows what to declare",
				transport.CodeMissingClientCapability, tasksExtension))
	default:
		return c.fail(Minor, "served tasks/get to a client that did not declare the Tasks extension",
			fmt.Sprintf("return %d for task methods from a client that did not declare %s", transport.CodeMissingClientCapability, tasksExtension))
	}
}

func toolParams(tool ToolResult) map[string]any {
	args := tool.Arguments
	if args == nil {
		args = map[string]any{}
	}
	return map[string]any{"name": tool.Name, "arguments": args}
}

func checkTaskUndeclared(ctx context.Context, s *Session, tool ToolResult) Finding {
	c := taskUndeclaredCheck(s)
	resp, err := s.taskCall(ctx, "tools/call undeclared "+tool.Name, "tools/call", toolParams(tool), false)
	switch {
	case err != nil:
		return c.info("request failed: " + truncate(err.Error(), 100))
	case resp.Error != nil:
		return c.info(fmt.Sprintf("%s answered error %d without the capability declared", tool.Name, resp.Error.Code))
	case transport.ResultType(resp.Result) == "task":
		return c.fail(Major, fmt.Sprintf("returned a task for %s to a client that did not declare %s", tool.Name, tasksExtension),
			"return a task only when the request declares the extension; otherwise answer synchronously, or with -32021 if the call cannot be served without one. A client without task support has no way to retrieve the result")
	default:
		return c.pass(fmt.Sprintf("answered %s synchronously when the extension was not declared", tool.Name))
	}
}

// taskState is the part of a Task passmcp reads.
type taskState struct {
	ResultType     string          `json:"resultType"`
	TaskID         string          `json:"taskId"`
	Status         string          `json:"status"`
	CreatedAt      string          `json:"createdAt"`
	LastUpdatedAt  string          `json:"lastUpdatedAt"`
	TTL            json.RawMessage `json:"ttlMs"`
	PollIntervalMs *float64        `json:"pollIntervalMs"`
	Result         json.RawMessage `json:"result"`
	Error          json.RawMessage `json:"error"`
	InputRequests  json.RawMessage `json:"inputRequests"`
}

// shapeProblems lists what a Task object is missing, per the extension.
func (t taskState) shapeProblems(where string) []string {
	var p []string
	if strings.TrimSpace(t.TaskID) == "" {
		p = append(p, where+" has no taskId")
	}
	if !taskStatuses[t.Status] {
		p = append(p, fmt.Sprintf("%s has status %q", where, t.Status))
	}
	for name, v := range map[string]string{"createdAt": t.CreatedAt, "lastUpdatedAt": t.LastUpdatedAt} {
		if _, err := time.Parse(time.RFC3339, v); err != nil {
			p = append(p, fmt.Sprintf("%s has no ISO 8601 %s", where, name))
		}
	}
	if len(t.TTL) == 0 {
		p = append(p, where+" has no ttlMs (it is required, null meaning unlimited)")
	} else if s := string(t.TTL); s != "null" {
		var n float64
		if json.Unmarshal(t.TTL, &n) != nil {
			p = append(p, fmt.Sprintf("%s has ttlMs %s, which is neither a number nor null", where, s))
		}
	}
	switch t.Status {
	case "completed":
		if !isJSONObject(t.Result) {
			p = append(p, where+" is completed with no result object")
		}
	case "failed":
		if !isJSONObject(t.Error) {
			p = append(p, where+" is failed with no error object")
		}
	case "input_required":
		if !isJSONObject(t.InputRequests) || string(t.InputRequests) == "{}" {
			p = append(p, where+" requires input but lists no inputRequests")
		}
	}
	return p
}

func isJSONObject(b json.RawMessage) bool {
	var m map[string]json.RawMessage
	return len(b) > 0 && json.Unmarshal(b, &m) == nil && m != nil
}

func (t taskState) interval() time.Duration {
	if t.PollIntervalMs == nil || *t.PollIntervalMs <= 0 {
		return taskPollDefault
	}
	d := time.Duration(*t.PollIntervalMs * float64(time.Millisecond))
	return min(max(d, taskPollMin), taskPollMax)
}

// getTask polls once. The problems it returns are about the response shape;
// an error return means passmcp could not read an answer at all.
func (s *Session) getTask(ctx context.Context, id string) (taskState, []string, error) {
	resp, err := s.taskCall(ctx, "tasks/get", "tasks/get", map[string]any{"taskId": id}, true)
	if err != nil {
		return taskState{}, nil, err
	}
	if resp.Error != nil {
		return taskState{}, []string{fmt.Sprintf("tasks/get for %s failed with error %d: %s", id, resp.Error.Code, truncate(resp.Error.Message, 80))}, nil //nolint:nilerr // the server's JSON-RPC error is the finding, not a failure to reach it
	}
	var t taskState
	if err := json.Unmarshal(resp.Result, &t); err != nil {
		return taskState{}, []string{"tasks/get returned something that is not a Task object"}, nil //nolint:nilerr // an unreadable result is the finding, not a failure to reach it
	}
	p := t.shapeProblems("tasks/get")
	if t.ResultType != transport.ResultComplete {
		p = append(p, fmt.Sprintf("tasks/get has resultType %q; the extension requires %q on it", t.ResultType, transport.ResultComplete))
	}
	if t.TaskID != "" && t.TaskID != id {
		p = append(p, fmt.Sprintf("tasks/get for %s answered about %s", id, t.TaskID))
	}
	return t, p, nil
}

func checkTaskLifecycle(ctx context.Context, s *Session, tool ToolResult) Finding {
	c := taskLifecycleCheck(s)
	created, problems, done := startTask(ctx, s, c, tool)
	if done != nil {
		return *done
	}
	id := created.TaskID
	start := time.Now()

	// Durable creation: the extension forbids returning the handle before
	// tasks/get would resolve it, so the first poll is immediate.
	state, p, err := s.getTask(ctx, id)
	if err != nil {
		return c.info("tasks/get failed: " + truncate(err.Error(), 100))
	}
	if len(p) > 0 && state.TaskID == "" {
		problems = append(problems, "the task was not retrievable immediately after it was returned: "+p[0])
		return c.fail(Major, strings.Join(problems, "; "),
			"create the task durably before returning its handle; the extension requires that tasks/get resolve it at once")
	}
	problems = append(problems, p...)

	state, problems, polls, done := s.followTask(ctx, c, id, state, problems, start.Add(taskPollBudget))
	if done != nil {
		return *done
	}
	return settleTask(ctx, s, c, tool, id, state, problems, polls, start)
}

// startTask calls the tool with the Tasks extension declared and reads the
// task it creates. done is the finding to return when there is no task to
// follow: the call failed, was refused, was answered synchronously, or
// created something that is not a usable task. Otherwise problems holds
// what is already wrong with the CreateTaskResult's shape.
func startTask(ctx context.Context, s *Session, c *check, tool ToolResult) (created taskState, problems []string, done *Finding) {
	stop := func(f Finding) (taskState, []string, *Finding) { return taskState{}, nil, &f }
	resp, err := s.taskCall(ctx, "tools/call declared "+tool.Name, "tools/call", toolParams(tool), true)
	switch {
	case err != nil:
		return stop(c.info("request failed: " + truncate(err.Error(), 100)))
	case resp.Error != nil:
		return stop(c.warn(fmt.Sprintf("%s fails with error %d when the Tasks extension is declared, and succeeds without it", tool.Name, resp.Error.Code),
			"declaring an extension must not break a call the server otherwise serves: answer synchronously or with a task"))
	case transport.ResultType(resp.Result) != "task":
		return stop(c.skip(fmt.Sprintf("the server answered %s synchronously with the extension declared; a server decides per call whether to create a task, so there was no lifecycle to follow", tool.Name)))
	}

	if err := json.Unmarshal(resp.Result, &created); err != nil {
		return stop(c.fail(Major, "resultType is \"task\" but the result is not a Task object", "return a CreateTaskResult: taskId, status, createdAt, lastUpdatedAt and ttlMs"))
	}
	problems = created.shapeProblems("the CreateTaskResult")
	if created.TaskID == "" {
		return stop(c.fail(Major, strings.Join(problems, "; "), "every CreateTaskResult needs the taskId the client polls with"))
	}
	return created, problems, nil
}

// followTask polls a task until it is terminal, needs input, shows a shape
// problem, or would outlast the deadline, and returns where it got to and
// how many polls that took. done is the finding to return when the run was
// cancelled or a poll could not be read.
func (s *Session) followTask(ctx context.Context, c *check, id string, state taskState, problems []string, deadline time.Time) (taskState, []string, int, *Finding) {
	polls := 1
	for !taskTerminal[state.Status] && state.Status != "input_required" && len(problems) == 0 {
		if time.Now().Add(state.interval()).After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			f := c.info("run cancelled while following the task")
			return state, problems, polls, &f
		case <-time.After(state.interval()):
		}
		var p []string
		var err error
		state, p, err = s.getTask(ctx, id)
		polls++
		if err != nil {
			f := c.info("tasks/get failed: " + truncate(err.Error(), 100))
			return state, problems, polls, &f
		}
		problems = append(problems, p...)
	}
	return state, problems, polls, nil
}

// settleTask judges where the task got to: shape problems fail it, a task
// needing input or still running is cancelled and reported, and a terminal
// task is asked once more to confirm it stays terminal.
func settleTask(ctx context.Context, s *Session, c *check, tool ToolResult, id string, state taskState, problems []string, polls int, start time.Time) Finding {
	if len(problems) > 0 {
		s.cancelTask(ctx, id)
		return c.fail(Major, dedupeStrings(problems),
			"follow the Tasks extension's shapes: every Task carries taskId, status, createdAt, lastUpdatedAt and ttlMs; completed carries result, failed carries error, input_required carries inputRequests, and tasks/get answers with resultType \"complete\"")
	}

	switch {
	case state.Status == "input_required":
		ack := s.cancelTask(ctx, id)
		return c.info(fmt.Sprintf("%s's task %s reached input_required after %d poll(s); passmcp has no user or model to answer it, so it cancelled the task (%s). Everything up to that point followed the extension",
			tool.Name, id, polls, ack))
	case !taskTerminal[state.Status]:
		ack := s.cancelTask(ctx, id)
		return c.warn(fmt.Sprintf("%s's task %s was still %s after %s and %d poll(s); passmcp cancelled it (%s)",
			tool.Name, id, state.Status, taskPollBudget, polls, ack),
			"a task backing a read-only call should finish promptly or report progress in statusMessage; one that never reaches a terminal state looks to an agent like a call that hangs")
	}

	// Terminal states are final. Ask once more.
	again, p, err := s.getTask(ctx, id)
	switch {
	case err != nil:
		return c.info("tasks/get after completion failed: " + truncate(err.Error(), 100))
	case len(p) > 0:
		return c.fail(Major, "after reaching "+state.Status+": "+dedupeStrings(p),
			"keep a terminal task retrievable, unchanged, until its ttlMs elapses")
	case again.Status != state.Status:
		return c.fail(Major, fmt.Sprintf("task %s was %s and then %s; terminal states must not change", id, state.Status, again.Status),
			"once a task is completed, failed or cancelled, every later tasks/get must report the same state")
	}
	return c.pass(fmt.Sprintf("%s's task %s reached %s in %s after %d poll(s), and stayed there",
		tool.Name, id, state.Status, ms(time.Since(start)), polls))
}

// cancelTask cancels a task passmcp started and did not see finish, and says
// how the server acknowledged it. Cancellation is cooperative, so the
// acknowledgement is what can be checked, not the outcome.
func (s *Session) cancelTask(ctx context.Context, id string) string {
	resp, err := s.taskCall(ctx, "tasks/cancel", "tasks/cancel", map[string]any{"taskId": id}, true)
	switch {
	case err != nil:
		return "tasks/cancel failed: " + truncate(err.Error(), 60)
	case resp.Error != nil:
		return fmt.Sprintf("tasks/cancel was refused with error %d", resp.Error.Code)
	case transport.ResultType(resp.Result) != transport.ResultComplete:
		return "tasks/cancel was acknowledged without resultType \"complete\""
	default:
		return "cancellation acknowledged"
	}
}

func dedupeStrings(in []string) string {
	var out []string
	for _, v := range in {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return strings.Join(out, "; ")
}
