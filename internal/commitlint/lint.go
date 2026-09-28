// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package commitlint implements AGENTS.md section 4: the commit header
// grammar, the fifty-character subject limit, imperative mood, and the
// seventy-two-character body wrap.
//
// The rule has been in AGENTS.md all along and nothing enforced it, so it
// decayed: thirty-seven of the forty commits before this package existed
// exceed the subject limit. That is what REPO-STANDARD predicts in its own
// opening — a standard that is not a CI gate decays — and the fix is a gate.
//
// Two details make the rule workable rather than merely strict. A squash
// merge appends " (#123)" to the subject, so the limit is measured with that
// suffix removed; otherwise the real budget is forty-four characters and
// nobody is told. And the body wrap exempts what cannot be wrapped: git
// trailers, bare URLs, and indented blocks such as a quoted command.
package commitlint

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// The limits, from AGENTS.md section 4.
const (
	SubjectMax = 50
	BodyMax    = 72
)

// Types are the allowed commit types. AGENTS.md lists exactly these.
var Types = []string{"feat", "fix", "docs", "style", "refactor", "perf", "test", "build", "ci", "chore"}

// header matches "<type>: <subject>" and "<type>(<scope>): <subject>".
//
// AGENTS.md's grammar omits the scope and does not forbid it; this repository
// has used scopes throughout. Allowing them is the reading that keeps the
// existing convention legible, and it is recorded here rather than left to
// each contributor to guess.
var header = regexp.MustCompile(`^(` + strings.Join(Types, "|") + `)(\([a-z0-9._/-]+\))?!?: (.+)$`)

// squashSuffix is what a squash merge appends. It is not the author's to
// budget for, so it comes off before the subject is measured.
var squashSuffix = regexp.MustCompile(`\s\(#\d+\)$`)

// notImperative catches the handful of openings that are reliably wrong.
// A general mood checker would need a dictionary and would be wrong often
// enough to be ignored, which is worse than checking less.
var notImperative = regexp.MustCompile(`^(Added|Adds|Adding|Fixed|Fixes|Fixing|Updated|Updates|Updating|Changed|Removes|Removed|Bumped) `)

// generatedBy are the authors whose messages a bot writes to its own
// template. Dependabot's subject is "bump <module> from <v> to <v>", which a
// long module path puts past the limit whatever its configuration says, so
// judging it would fail every dependency update on something no contributor
// wrote. Matched on the bot's GitHub noreply address, which a person cannot
// commit as through the web and would have to forge locally to borrow.
var generatedBy = map[string]bool{
	"49699333+dependabot[bot]@users.noreply.github.com": true,
}

// Generated reports whether a commit's message was written by a bot rather
// than a contributor, so it is not theirs to be judged on. The same reason
// the command skips platform merge commits.
func Generated(authorEmail string) bool {
	return generatedBy[strings.ToLower(strings.TrimSpace(authorEmail))]
}

// trailer matches a git trailer, which may be any length.
var trailer = regexp.MustCompile(`^[A-Za-z-]+: `)

// Lint returns every problem with one commit message, body included. The
// argument is the message without its subject-line prefix stripped: lines[0]
// is the subject.
func Lint(lines []string) []string {
	var out []string
	subject := strings.TrimRight(lines[0], " \t")

	if m := header.FindStringSubmatch(subject); m == nil {
		out = append(out, fmt.Sprintf("subject %q is not \"<type>: <subject>\"; allowed types: %s",
			truncate(subject), strings.Join(Types, ", ")))
	} else {
		measured := squashSuffix.ReplaceAllString(subject, "")
		if n := utf8.RuneCountInString(measured); n > SubjectMax {
			out = append(out, fmt.Sprintf("subject is %d characters, limit %d: %q", n, SubjectMax, truncate(measured)))
		}
		if notImperative.MatchString(m[3]) {
			out = append(out, fmt.Sprintf("subject is not imperative: %q — say \"add\", not \"added\"", truncate(m[3])))
		}
		if strings.HasSuffix(measured, ".") {
			out = append(out, "subject ends with a full stop")
		}
	}

	if len(lines) > 1 && strings.TrimSpace(lines[1]) != "" {
		out = append(out, "no blank line between the subject and the body")
	}

	for i, line := range lines[1:] {
		if utf8.RuneCountInString(line) <= BodyMax {
			continue
		}
		switch {
		case trailer.MatchString(line):
			// Co-Authored-By and friends cannot wrap.
		case strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t"):
			// An indented block is a command or a log line, quoted verbatim.
		case strings.Contains(line, "://"):
			// A URL that is wrapped is a URL that does not work.
		default:
			out = append(out, fmt.Sprintf("body line %d is %d characters, limit %d: %q",
				i+2, utf8.RuneCountInString(line), BodyMax, truncate(line)))
		}
	}
	return out
}

func truncate(s string) string {
	const n = 60
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}
