// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"satellion.com/passmcp"
)

// Model is the language model the agentic probe drives. Implementations
// adapt a vendor SDK; the package ships none so it stays dependency-free.
type Model interface {
	// Step returns the model's next action given the conversation so far.
	Step(ctx context.Context, conv *Conversation) (Action, error)
}

// Conversation is the transcript handed to the model on each turn.
type Conversation struct {
	System string
	Task   string
	Tools  []passmcp.Tool
	Turns  []Turn
}

// Turn is one model action and, for tool calls, the observed result.
type Turn struct {
	Action Action
	Result string
	Error  string
}

// Action is what the model decided to do.
type Action struct {
	// ToolName, when set, requests a tool call with Arguments.
	ToolName  string
	Arguments map[string]any
	// Final, when ToolName is empty, is the model's answer.
	Final string
}

// AgentBudget bounds the agentic probe.
type AgentBudget struct {
	MaxTurns     int
	MaxToolCalls int
	// MaxRepeats is how many identical (tool, args) calls are tolerated
	// before the loop is declared stuck.
	MaxRepeats int
	// TurnTimeout bounds one model step plus tool call.
	TurnTimeout time.Duration
}

// DefaultAgentBudget is conservative enough for third-party servers.
var DefaultAgentBudget = AgentBudget{MaxTurns: 5, MaxToolCalls: 8, MaxRepeats: 2, TurnTimeout: 60 * time.Second}

// AgentOutcome summarises the agentic probe.
type AgentOutcome struct {
	Completed   bool     `json:"completed"`
	Turns       int      `json:"turns"`
	ToolCalls   int      `json:"tool_calls"`
	FailedCalls int      `json:"failed_calls"`
	Final       string   `json:"final,omitempty"`
	Findings    []string `json:"findings,omitempty"`
	Transcript  []Turn   `json:"transcript,omitempty"`
}

// ErrBudgetExhausted is recorded (not returned) when the loop is halted.
var ErrBudgetExhausted = errors.New("llm budget exhausted")

// caller abstracts the client so the agent loop is testable.
type caller interface {
	CallTool(ctx context.Context, name string, args any) (*passmcp.CallToolResult, error)
}

// runAgent drives model against tools through client, under budget and
// policy. Policy decisions apply to the model's calls exactly as they do
// to synthetic ones: a refused call is fed back to the model as an error.
func runAgent(ctx context.Context, client caller, model Model, tools []passmcp.Tool, task string, budget AgentBudget, policy Policy, limiter *Limiter) *AgentOutcome {
	a := &agentRun{
		out: &AgentOutcome{},
		conv: &Conversation{
			System: "You are validating an MCP server. Use the available tools to accomplish the task. Stop when done or when tools are not useful.",
			Task:   task,
			Tools:  tools,
		},
		byName: map[string]passmcp.Tool{},
		seen:   map[string]int{},
		client: client, model: model, budget: budget, policy: policy, limiter: limiter,
	}
	for _, t := range tools {
		a.byName[t.Name] = t
	}
	for a.out.Turns < budget.MaxTurns {
		if a.turn(ctx) {
			return a.out
		}
	}
	a.out.Findings = append(a.out.Findings, fmt.Sprintf("turn cap %d reached without a final answer: %v", budget.MaxTurns, ErrBudgetExhausted))
	a.out.Transcript = a.conv.Turns
	return a.out
}

// agentRun is the state of one agentic probe: the outcome being built, the
// conversation the model sees, and the budget, policy and limiter every
// call goes through.
type agentRun struct {
	out     *AgentOutcome
	conv    *Conversation
	byName  map[string]passmcp.Tool
	seen    map[string]int
	client  caller
	model   Model
	budget  AgentBudget
	policy  Policy
	limiter *Limiter
}

// turn asks the model for one action and carries it out, reporting whether
// the loop is over: a final answer, a model error, or a budget stop.
func (a *agentRun) turn(ctx context.Context) bool {
	a.out.Turns++
	tctx, cancel := context.WithTimeout(ctx, a.budget.TurnTimeout)
	defer cancel()
	act, err := a.model.Step(tctx, a.conv)
	if err != nil {
		a.out.Findings = append(a.out.Findings, "model error: "+err.Error())
		return true
	}
	if act.ToolName == "" {
		a.out.Completed, a.out.Final = true, act.Final
		a.conv.Turns = append(a.conv.Turns, Turn{Action: act})
		a.out.Transcript = a.conv.Turns
		return true
	}
	turn := Turn{Action: act}
	tool, known := a.byName[act.ToolName]
	switch {
	case !known:
		turn.Error = "unknown tool"
		a.out.Findings = append(a.out.Findings, fmt.Sprintf("agent called unknown tool %q: descriptions may be misleading", act.ToolName))
	case !a.policy.Decide(tool).Execute:
		turn.Error = "tool blocked by safety policy"
	default:
		if a.invoke(tctx, act, tool, &turn) {
			return true
		}
	}
	a.conv.Turns = append(a.conv.Turns, turn)
	return false
}

// invoke makes the call the model asked for, unless it repeats itself past
// the budget, the call cap is reached, or the limiter gives up; it reports
// whether the loop must stop.
func (a *agentRun) invoke(tctx context.Context, act Action, tool passmcp.Tool, turn *Turn) bool {
	if issues := validateArgs(tool, act.Arguments); len(issues) > 0 {
		a.out.Findings = append(a.out.Findings, fmt.Sprintf("agent produced invalid arguments for %s: %v (schema may be unclear)", tool.Name, issues))
	}
	key := act.ToolName + ":" + stableJSON(act.Arguments)
	a.seen[key]++
	if a.seen[key] > a.budget.MaxRepeats {
		a.out.Findings = append(a.out.Findings, fmt.Sprintf("agent repeated %s with identical arguments %d times: %v", act.ToolName, a.seen[key], ErrBudgetExhausted))
		a.conv.Turns = append(a.conv.Turns, *turn)
		a.out.Transcript = a.conv.Turns
		return true
	}
	if a.out.ToolCalls >= a.budget.MaxToolCalls {
		a.out.Findings = append(a.out.Findings, fmt.Sprintf("tool call cap %d reached: %v", a.budget.MaxToolCalls, ErrBudgetExhausted))
		a.out.Transcript = a.conv.Turns
		return true
	}
	if err := a.limiter.Wait(tctx); err != nil {
		a.out.Findings = append(a.out.Findings, "cancelled: "+err.Error())
		a.out.Transcript = a.conv.Turns
		return true
	}
	a.out.ToolCalls++
	res, err := a.client.CallTool(tctx, act.ToolName, act.Arguments)
	switch {
	case err != nil:
		a.out.FailedCalls++
		turn.Error = err.Error()
	case res.IsError:
		a.out.FailedCalls++
		turn.Error = "tool error: " + res.Text()
	default:
		turn.Result = res.Text()
		if len(res.StructuredContent) > 0 {
			turn.Result += "\n" + string(res.StructuredContent)
		}
	}
	return false
}

func validateArgs(t passmcp.Tool, args map[string]any) []string {
	if len(t.InputSchema) == 0 {
		return nil
	}
	b, err := json.Marshal(args)
	if err != nil {
		return []string{err.Error()}
	}
	return Validate(t.InputSchema, b)
}

func stableJSON(v any) string {
	b, _ := json.Marshal(v) // encoding/json sorts map keys
	return string(b)
}
