// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package commitlint

import (
	"strings"
	"testing"
)

// msg assembles a commit message from a subject and body lines.
func msg(lines ...string) []string { return lines }

func TestGeneratedIsOnlyTheBot(t *testing.T) {
	for email, want := range map[string]bool{
		"49699333+dependabot[bot]@users.noreply.github.com":   true,
		" 49699333+Dependabot[bot]@users.noreply.github.com ": true,
		"dependabot@example.com":                              false,
		"sebastian.rousseau@gmail.com":                        false,
		"":                                                    false,
	} {
		if got := Generated(email); got != want {
			t.Errorf("Generated(%q) = %v", email, got)
		}
	}
}

func TestLintAcceptsACompliantCommit(t *testing.T) {
	for _, subject := range []string{
		"feat: add a stdio transport",
		"fix(cli): reject two targets at once",
		"docs: record why there is no KEYS.asc",
		"refactor(transport)!: drop the Do method",
	} {
		if got := Lint(msg(subject, "", "A body that explains what and why, wrapped well", "inside the limit.")); len(got) > 0 {
			t.Errorf("%q was rejected: %v", subject, got)
		}
	}
}

func TestLintRejects(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{
			name: "a subject over the limit",
			in:   msg("feat(report): carry the guidance into the text and Markdown renderings"),
			want: "limit 50",
		},
		{
			name: "a type AGENTS.md does not list",
			in:   msg("wip: something"),
			want: "is not \"<type>: <subject>\"",
		},
		{
			name: "no type at all",
			in:   msg("just a sentence"),
			want: "is not \"<type>: <subject>\"",
		},
		{
			name: "a past-tense subject",
			in:   msg("feat: Added the stdio transport"),
			want: "not imperative",
		},
		{
			name: "a subject ending in a full stop",
			in:   msg("feat: add the stdio transport."),
			want: "full stop",
		},
		{
			name: "no blank line before the body",
			in:   msg("feat: add the stdio transport", "Straight into the body."),
			want: "no blank line",
		},
		{
			name: "a body line over the wrap",
			in:   msg("feat: add a transport", "", strings.Repeat("x", 73)),
			want: "limit 72",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Lint(tc.in)
			if len(got) == 0 {
				t.Fatalf("accepted %s", tc.name)
			}
			if !strings.Contains(strings.Join(got, "; "), tc.want) {
				t.Errorf("problems do not mention %q: %v", tc.want, got)
			}
		})
	}
}

// TestSquashSuffixIsNotTheAuthorsBudget is the detail that makes the rule
// usable rather than merely strict.
//
// A squash merge appends " (#123)". If the limit were measured with it, the
// real budget would be forty-four characters and no error message would ever
// say so — an author would shorten a subject, watch it fail again after
// merge, and conclude the linter was broken.
func TestSquashSuffixIsNotTheAuthorsBudget(t *testing.T) {
	// Exactly at the limit before the suffix, over it afterwards.
	subject := "feat: add a stdio transport to the client"
	if n := len(subject); n > SubjectMax {
		t.Fatalf("fixture is already %d characters; it cannot test the exemption", n)
	}
	if got := Lint(msg(subject + " (#1234)")); len(got) > 0 {
		t.Errorf("the squash suffix was counted against the author: %v", got)
	}
	// And the exemption is narrow: a parenthetical that is not a PR
	// reference is the author's own text and does count.
	long := "feat: add a stdio transport to the client (eventually)"
	if got := Lint(msg(long)); len(got) == 0 {
		t.Errorf("a non-PR parenthetical was exempted; %q is %d characters", long, len(long))
	}
}

// TestBodyWrapExemptions: three kinds of line cannot be wrapped, and a
// linter that demands it anyway is one contributors learn to bypass.
func TestBodyWrapExemptions(t *testing.T) {
	long := "satellion.com/passmcp/internal/report/remediation.go"
	cases := map[string]string{
		"a git trailer":     "Reviewed-by: A Maintainer With A Fairly Long Name <maintainer@example.com>",
		"a bare URL":        "See https://example.com/" + long,
		"an indented block": "    passmcp check --stdio -- npx -y @modelcontextprotocol/server-everything stdio",
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			if len([]rune(line)) <= BodyMax {
				t.Fatalf("fixture is only %d characters; it cannot test the exemption", len([]rune(line)))
			}
			if got := Lint(msg("feat: add a transport", "", line)); len(got) > 0 {
				t.Errorf("%s was flagged: %v", name, got)
			}
		})
	}
}
