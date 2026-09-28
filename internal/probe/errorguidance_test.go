// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"encoding/json"
	"strings"
	"testing"

	"satellion.com/passmcp"
)

// errSession builds a session carrying the isError results a run collected.
func errSession(tools []passmcp.Tool, errs map[string]string) *Session {
	s := session(tools)
	for name, msg := range errs {
		s.ToolResults = append(s.ToolResults, ToolResult{Name: name, Executed: true, ToolError: msg})
	}
	// Map iteration is unordered and a report that reorders between two
	// runs over the same server is a diff with no change in it.
	sortToolResults(s)
	return s
}

func sortToolResults(s *Session) {
	for i := 1; i < len(s.ToolResults); i++ {
		for j := i; j > 0 && s.ToolResults[j].Name < s.ToolResults[j-1].Name; j-- {
			s.ToolResults[j], s.ToolResults[j-1] = s.ToolResults[j-1], s.ToolResults[j]
		}
	}
}

// TestErrorGuidancePassesActionableErrors is the shape that lets a model
// recover without a human.
func TestErrorGuidancePassesActionableErrors(t *testing.T) {
	s := errSession(nil, map[string]string{
		"read_file":  "path must be an absolute path; use list_directory to find it",
		"get_issue":  "issue 4210 not found; valid values for state are open, closed, all",
		"search_log": "window must be between 1 and 30 days, got 400",
	})

	f := checkErrorGuidance(s)
	if f.Status != Pass {
		t.Fatalf("errors that name the fix were not passed: %+v", f)
	}
	if !strings.Contains(f.Detail, "3 explain what to change") {
		t.Errorf("the finding does not report the counts: %q", f.Detail)
	}
}

// TestErrorGuidanceFailsAStackTrace: the caller gets nothing usable, and
// learns the server's file layout on the way.
func TestErrorGuidanceFailsAStackTrace(t *testing.T) {
	s := errSession(nil, map[string]string{
		"read_file": "Traceback (most recent call last):\n  File \"/srv/app/handlers.py\", line 214, in read_file\n    raise KeyError(path)\nKeyError: '/etc/x'",
	})

	f := checkErrorGuidance(s)
	if f.Status != Fail {
		t.Fatalf("a stack trace on the wire was not failed: %+v", f)
	}
	if f.Severity != Major {
		t.Errorf("want Major, got %v", f.Severity)
	}
	if !strings.Contains(f.Detail, "internal trace") {
		t.Errorf("the finding does not say what was wrong: %q", f.Detail)
	}
}

// TestErrorGuidanceWarnsOnBareErrors: correct rejection, useless text.
func TestErrorGuidanceWarnsOnBareErrors(t *testing.T) {
	s := errSession(nil, map[string]string{
		"a_tool": "error",
		"b_tool": "Invalid input.",
		"c_tool": "500",
	})

	f := checkErrorGuidance(s)
	if f.Status != Warn {
		t.Fatalf("errors that say only that something failed were not warned: %+v", f)
	}
	if !strings.Contains(f.Detail, "3 say only that it failed") {
		t.Errorf("the finding does not report the counts: %q", f.Detail)
	}
}

// TestErrorGuidanceSkipsWhenNothingWasRejected honours the rule that a
// check passes only on evidence: with no isError result there is no error
// text, and inventing a verdict would be the damaging move.
func TestErrorGuidanceSkipsWhenNothingWasRejected(t *testing.T) {
	s := session(nil)
	s.ToolResults = []ToolResult{{Name: "read_file", Executed: true, OK: true}}

	f := checkErrorGuidance(s)
	if f.Status != Skip {
		t.Fatalf("with no rejection to read, the check must skip rather than pass: %+v", f)
	}
	if f.Detail == "" {
		t.Error("a skip has to name its reason")
	}
}

// TestErrorGuidanceDoesNotPenaliseTheRejectionItself is the invariant
// AGENTS.md is explicit about: rejecting a generated argument is correct,
// and only the wording is graded.
func TestErrorGuidanceDoesNotPenaliseTheRejectionItself(t *testing.T) {
	s := errSession(nil, map[string]string{
		"create_issue": "repository \"probe\" does not exist; expected owner/name",
		"get_repo":     "repository \"probe\" not found; try a full owner/name slug",
	})

	f := checkErrorGuidance(s)
	if f.Status != Pass {
		t.Fatalf("well-worded rejections of generated arguments must pass, not count against the server: %+v", f)
	}
}

// TestErrorGuidanceReadsTheSchemaForParameterNames: an error naming the
// field it rejected is actionable even with no cue word in it.
func TestErrorGuidanceReadsTheSchemaForParameterNames(t *testing.T) {
	tools := []passmcp.Tool{{
		Name:        "search_log",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"retention_window":{"type":"integer"}}}`),
	}}
	s := errSession(tools, map[string]string{
		"search_log": "the retention_window you gave is outside what this deployment keeps",
	})

	f := checkErrorGuidance(s)
	if f.Status != Pass {
		t.Fatalf("an error naming the rejected parameter was not treated as actionable: %+v", f)
	}
}

// TestErrorGuidanceWarnsWhenMostAreBare: one good message does not carry a
// catalog.
func TestErrorGuidanceWarnsWhenMostAreBare(t *testing.T) {
	s := errSession(nil, map[string]string{
		"a_tool": "limit must be between 1 and 100",
		"b_tool": "error",
		"c_tool": "failed",
	})

	f := checkErrorGuidance(s)
	if f.Status != Warn {
		t.Fatalf("a catalog where bare errors outnumber useful ones was not warned: %+v", f)
	}
}

// TestGradeErrorClassifies covers the grader directly, including the
// language-specific trace shapes.
func TestGradeErrorClassifies(t *testing.T) {
	internal := []string{
		"Traceback (most recent call last):\n  File \"a.py\", line 2",
		"    at Object.handler (/srv/app/index.js:41:17)",
		"goroutine 17 [running]:",
		"panic: runtime error: index out of range",
		"java.lang.NullPointerException",
		"failure in handlers.go:214",
	}
	for _, m := range internal {
		if g := gradeError(m, nil); g != gradeInternal {
			t.Errorf("gradeError(%q) = %v, want internal", m, g)
		}
	}

	bare := []string{"error", "Failed.", "500", "invalid argument", "null", "x"}
	for _, m := range bare {
		if g := gradeError(m, nil); g != gradeBare {
			t.Errorf("gradeError(%q) = %v, want bare", m, g)
		}
	}

	actionable := []string{
		"path must be absolute",
		"state must be one of open, closed",
		"limit is required",
		"unknown repository; did you mean passmcp?",
		"try calling list_directory first",
	}
	for _, m := range actionable {
		if g := gradeError(m, nil); g != gradeActionable {
			t.Errorf("gradeError(%q) = %v, want actionable", m, g)
		}
	}
}

// TestErrorGuidanceTruncates: worst first, and at most three.
func TestErrorGuidanceTruncates(t *testing.T) {
	errs := map[string]string{}
	for _, n := range []string{"a_tool", "b_tool", "c_tool", "d_tool", "e_tool"} {
		errs[n] = "error"
	}
	errs["z_tool"] = "goroutine 1 [running]:"
	s := errSession(nil, errs)

	f := checkErrorGuidance(s)
	if f.Status != Fail {
		t.Fatalf("a trace among the errors did not fail the check: %+v", f)
	}
	if !strings.Contains(f.Detail, "z_tool") {
		t.Errorf("the worst error was not shown first: %q", f.Detail)
	}
	if !strings.Contains(f.Detail, "more") {
		t.Errorf("a long list was not truncated: %q", f.Detail)
	}
}
