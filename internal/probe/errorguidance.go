// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"satellion.com/passmcp"
)

// The consumer of an error message here is a model, and a model's only
// recovery path is to read the string and try something else. That makes
// error text a functional part of a server's interface rather than a
// courtesy: "invalid argument" ends the attempt, while "path must be
// absolute; use list_directory to find it" is a tool call away from
// working.
//
// passmcp already has the material. The execution phase invokes read-only
// tools with generated arguments, and a good server rejects a generated
// repository name — so the isError results are already there, and grading
// what they say costs no extra request.
//
// The distinction this check has to hold on to is the one AGENTS.md is
// explicit about: an isError result is not a failure. A tool that refuses
// "probe" as a repository name is behaving correctly, and nothing here
// counts the rejection against the server. What is graded is only whether
// the rejection said anything a caller could act on.

// stackTracePatterns are the shapes of an internal trace reaching the wire.
//
// Two separate problems: the model gets nothing it can use, and whoever
// called the tool now knows the server's file layout, its framework and
// often its dependency versions. A stack trace is the one error shape that
// is worse than saying nothing.
var stackTracePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)traceback \(most recent call last\)`),
	regexp.MustCompile(`(?m)^\s*File "[^"]+", line \d+`),
	regexp.MustCompile(`(?m)^\s+at [\w$.<>]+ ?\(.*:\d+:\d+\)`),
	regexp.MustCompile(`(?m)^goroutine \d+ \[`),
	regexp.MustCompile(`(?i)\b[\w./-]+\.(?:go|py|js|ts|rb|java|rs):\d+\b`),
	regexp.MustCompile(`(?i)\b(?:nullpointerexception|stacktrace|panic: )`),
	regexp.MustCompile(`(?i)at [\w.]+\.[\w$]+\([\w.]+\.java:\d+\)`),
}

// guidanceCues are the constructions that make an error actionable: they
// name what was expected, or what to do instead.
var guidanceCues = []string{
	"must be", "must not", "should be", "expected", "expects",
	"valid values", "allowed values", "one of", "supported",
	"required", "is required", "missing required", "instead",
	"try ", "use ", "call ", "provide ", "specify ", "did you mean",
	"has to be", "needs to be", "accepts", "between", "at most",
	"at least", "maximum", "minimum", "not found; ", "unknown ",
	"available ",
}

// barePhrases are complete errors that say only that something went wrong.
var barePhrases = map[string]bool{
	"error": true, "failed": true, "failure": true, "invalid": true,
	"invalid input": true, "invalid argument": true, "invalid arguments": true,
	"invalid request": true, "bad request": true, "internal error": true,
	"internal server error": true, "unexpected error": true,
	"an error occurred": true, "something went wrong": true, "null": true,
	"undefined": true, "none": true, "exception": true, "true": true,
	"false": true, "0": true, "1": true, "500": true, "400": true,
}

// errorGrade is how usable one error message is to the caller.
type errorGrade int

const (
	// gradeActionable names what was wrong or what to do instead.
	gradeActionable errorGrade = iota
	// gradeBare says only that something failed.
	gradeBare
	// gradeInternal leaks a trace instead of an explanation.
	gradeInternal
)

// gradedError is one isError result and what it was worth.
type gradedError struct {
	tool  string
	grade errorGrade
	quote string
}

// gradeError classifies one error string.
//
// schemaNames are the argument names of the tool that produced it: an
// error naming the parameter it rejected is actionable even when it is
// phrased without any of the cue words, because the caller now knows which
// field to change.
func gradeError(msg string, schemaNames []string) errorGrade {
	trimmed := strings.TrimSpace(msg)
	for _, re := range stackTracePatterns {
		if re.MatchString(trimmed) {
			return gradeInternal
		}
	}
	lower := strings.ToLower(trimmed)
	// A bare code or a stock phrase, with or without trailing punctuation.
	if barePhrases[strings.Trim(lower, " .!:;")] {
		return gradeBare
	}
	if len(trimmed) < 12 {
		return gradeBare
	}
	for _, cue := range guidanceCues {
		if strings.Contains(lower, cue) {
			return gradeActionable
		}
	}
	for _, n := range schemaNames {
		if n != "" && strings.Contains(lower, strings.ToLower(n)) {
			return gradeActionable
		}
	}
	return gradeBare
}

// argNamesOf lists the declared argument names of a tool.
func argNamesOf(tools []passmcp.Tool, name string) []string {
	for _, t := range tools {
		if t.Name != name {
			continue
		}
		var p struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if err := json.Unmarshal(t.InputSchema, &p); err != nil {
			return nil
		}
		out := make([]string, 0, len(p.Properties))
		for k := range p.Properties {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	return nil
}

// gradeToolErrors grades every isError result the run collected.
func gradeToolErrors(s *Session) []gradedError {
	var out []gradedError
	for _, tr := range s.ToolResults {
		if strings.TrimSpace(tr.ToolError) == "" {
			continue
		}
		out = append(out, gradedError{
			tool:  tr.Name,
			grade: gradeError(tr.ToolError, argNamesOf(s.Tools, tr.Name)),
			quote: truncate(strings.Join(strings.Fields(tr.ToolError), " "), 120),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		// Worst first, so the truncated list shows what matters.
		if out[i].grade != out[j].grade {
			return out[i].grade > out[j].grade
		}
		return out[i].tool < out[j].tool
	})
	return out
}

// checkErrorGuidance grades what a rejected call told the caller.
func checkErrorGuidance(s *Session) Finding {
	c := s.check("execution.error_guidance", "Rejected calls say how to succeed")

	graded := gradeToolErrors(s)
	if len(graded) == 0 {
		return c.skip("no tool returned isError, so there was no error text to read")
	}

	var actionable, bare, internal int
	for _, g := range graded {
		switch g.grade {
		case gradeActionable:
			actionable++
		case gradeBare:
			bare++
		case gradeInternal:
			internal++
		}
	}

	summary := fmt.Sprintf("%d rejected call(s): %d explain what to change, %d say only that it failed, %d return an internal trace",
		len(graded), actionable, bare, internal)

	switch {
	case internal > 0:
		return c.fail(Major, summary+"; "+describeGraded(graded),
			"return the reason instead of the exception. A trace tells the caller nothing it can act on "+
				"and tells it your file layout, framework and versions, which is a disclosure on a path "+
				"that is reachable by anyone who can call the tool")
	case actionable == 0:
		return c.warn(summary+"; "+describeGraded(graded),
			"name the argument that was wrong and what it should have been. The caller is a model, and "+
				"the error string is the only recovery path it has")
	case bare > actionable:
		return c.warn(summary+"; "+describeGraded(graded),
			"bring the rest up to the standard the best of them already set")
	default:
		return c.pass(summary)
	}
}

// describeGraded names at most three, worst first.
func describeGraded(graded []gradedError) string {
	var b strings.Builder
	shown := min(len(graded), 3)
	for i := range shown {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "%s returned %q", graded[i].tool, graded[i].quote)
	}
	if len(graded) > shown {
		fmt.Fprintf(&b, "; and %d more", len(graded)-shown)
	}
	return b.String()
}
