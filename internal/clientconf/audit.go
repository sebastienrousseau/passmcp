// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package clientconf

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// A stdio server's launch command is decided before the server answers a
// single request, and it is where published attacks on MCP hosts have been
// found: a command run through a shell, a script fetched and piped into
// one, an `npx` package with no version so whatever is published next runs
// next, and a credential written into the arguments where every process
// listing shows it. Each is lexical, so it can be read without starting
// anything.

// IssueKind names what is wrong with a launch command.
type IssueKind string

// The launch-configuration issues.
const (
	// IssueShell is a command run through a shell, or an argument a shell
	// would expand.
	IssueShell IssueKind = "shell-interpolation"
	// IssuePipeToShell is a launcher that downloads a script and runs it.
	IssuePipeToShell IssueKind = "download-and-run"
	// IssueUnpinned is a package runner with no version.
	IssueUnpinned IssueKind = "unpinned-package"
	// IssueSecretArg is a credential passed as an argument.
	IssueSecretArg IssueKind = "secret-in-arguments"
)

// Issue is one finding in one server's launch command.
type Issue struct {
	Server string    `json:"server"`
	Kind   IssueKind `json:"kind"`
	// Line is the 1-based line in the configuration file.
	Line int `json:"line"`
	// Detail says what was found. It never contains a secret's value.
	Detail string `json:"detail"`
}

// Audit reads every stdio server's launch command for the four issues.
func (c *Config) Audit() []Issue {
	if c == nil {
		return nil
	}
	var out []Issue
	for _, s := range c.Servers {
		if !s.Stdio() {
			continue
		}
		out = append(out, auditShell(s)...)
		out = append(out, auditPipe(s)...)
		out = append(out, auditUnpinned(s)...)
		out = append(out, auditSecrets(s)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Server != out[j].Server {
			return out[i].Server < out[j].Server
		}
		return out[i].Line < out[j].Line
	})
	return out
}

// argLine is the line of argument i, falling back to the command's.
func argLine(s Server, i int) int {
	if i >= 0 && i < len(s.ArgLines) && s.ArgLines[i] > 0 {
		return s.ArgLines[i]
	}
	if s.CommandLine > 0 {
		return s.CommandLine
	}
	return s.Line
}

var shells = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "fish": true,
	"cmd": true, "cmd.exe": true, "powershell": true, "powershell.exe": true, "pwsh": true,
}

// expansionRe matches what a shell would expand: command substitution,
// backticks and parameter expansion. ${input:…} and ${env:…} are VS Code's
// own substitution syntax, resolved by the host rather than a shell, and are
// left alone. Hosts exec the command directly, so an expansion is only
// interpolated when the command is itself a shell; elsewhere it is passed
// literally and is not reported.
var expansionRe = regexp.MustCompile("\\$\\((?:.|\\n)*?\\)|`[^`]+`|\\$\\{(?:[A-Za-z_][A-Za-z0-9_]*)\\}|\\$[A-Za-z_][A-Za-z0-9_]*")

func auditShell(s Server) []Issue {
	var out []Issue
	base := strings.ToLower(path.Base(strings.ReplaceAll(s.Command, `\`, "/")))
	if !shells[base] {
		return nil
	}
	for i, a := range s.Args {
		if a == "-c" || strings.EqualFold(a, "/c") || strings.EqualFold(a, "-Command") {
			out = append(out, Issue{Server: s.Name, Kind: IssueShell, Line: argLine(s, i),
				Detail: fmt.Sprintf("started through %s %s, so the rest of the command is interpreted by a shell", base, a)})
			break
		}
	}
	for i, a := range s.Args {
		if m := expansionRe.FindString(a); m != "" {
			out = append(out, Issue{Server: s.Name, Kind: IssueShell, Line: argLine(s, i),
				Detail: fmt.Sprintf("argument %d contains %q, which a shell would expand", i+1, clip(m))})
		}
	}
	return out
}

// pipeRe matches a download piped into an interpreter, in POSIX shells and
// in PowerShell.
var pipeRe = regexp.MustCompile(`(?i)\b(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|dash|python3?|node|iex|invoke-expression)\b`)

func auditPipe(s Server) []Issue {
	line := strings.Join(append([]string{s.Command}, s.Args...), " ")
	if m := pipeRe.FindString(line); m != "" {
		i := len(s.Args) - 1
		for j, a := range s.Args {
			if pipeRe.MatchString(a) || strings.Contains(a, "|") {
				i = j
				break
			}
		}
		return []Issue{{Server: s.Name, Kind: IssuePipeToShell, Line: argLine(s, i),
			Detail: fmt.Sprintf("downloads and runs a script (%q): what runs is whatever that URL serves at launch", clip(maskQuery(m)))}}
	}
	return nil
}

// runners are package runners that fetch a package at launch, and the
// flags of each that take a value, so the value is not mistaken for the
// package.
var runners = map[string]map[string]bool{
	"npx":  {"-p": false, "--package": false, "-c": true, "--call": true},
	"bunx": {"-p": false, "--package": false},
	"uvx":  {"--from": false, "--with": true, "--python": true, "-p": true, "--index": true, "--index-url": true},
	"pipx": {"--spec": false, "--python": true, "--index-url": true},
	"dlx":  {},
}

func auditUnpinned(s Server) []Issue {
	cmd := strings.ToLower(path.Base(strings.ReplaceAll(s.Command, `\`, "/")))
	args := s.Args
	offset := 0
	switch cmd {
	case "pnpm", "yarn":
		if len(args) == 0 || args[0] != "dlx" {
			return nil
		}
		cmd, args, offset = "dlx", args[1:], 1
	case "pipx":
		if len(args) == 0 || args[0] != "run" {
			return nil
		}
		args, offset = args[1:], 1
	}
	valued, ok := runners[cmd]
	if !ok {
		return nil
	}
	i, pkg := packageArg(args, valued)
	if pkg == "" {
		return nil
	}
	if pinned(cmd, pkg) {
		return nil
	}
	return []Issue{{Server: s.Name, Kind: IssueUnpinned, Line: argLine(s, i+offset),
		Detail: fmt.Sprintf("%s runs %q with no version, so each launch runs whatever was published last", cmd, clip(pkg))}}
}

// packageArg finds the package a runner will fetch: the value of
// --from/--spec when given, else the first argument that is not a flag.
func packageArg(args []string, valued map[string]bool) (int, string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, val, hasEq := strings.Cut(a, "=")
		takesValue, known := valued[name]
		switch {
		case known && !takesValue: // --from / --spec name the package itself
			return flagValue(args, i, val, hasEq)
		case known:
			if !hasEq {
				i++
			}
		case !strings.HasPrefix(a, "-"):
			return i, a
		}
	}
	return -1, ""
}

// flagValue is the value of the flag at i: after its =, or the next
// argument.
func flagValue(args []string, i int, val string, hasEq bool) (int, string) {
	switch {
	case hasEq:
		return i, val
	case i+1 < len(args):
		return i + 1, args[i+1]
	}
	return -1, ""
}

var versionRe = regexp.MustCompile(`\d`)

// pinned reports whether a package spec names a version.
func pinned(cmd, pkg string) bool {
	switch cmd {
	case "uvx", "pipx":
		// == and @ pin one version; >= and ~= are ranges, which is not
		// pinning.
		for _, sep := range []string{"===", "==", "@"} {
			if _, v, ok := strings.Cut(pkg, sep); ok && versionRe.MatchString(v) {
				return true
			}
		}
		return false
	}
	// npm: name@version, where a scoped name starts with its own @.
	_, v, ok := strings.Cut(strings.TrimPrefix(pkg, "@"), "@")
	if !ok {
		return strings.HasPrefix(pkg, ".") || strings.HasPrefix(pkg, "/") // a local path
	}
	return versionRe.MatchString(v) && v != "latest"
}

// secretFlagRe matches an argument that names a credential.
var secretFlagRe = regexp.MustCompile(`(?i)^--?[a-z0-9_-]*(token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)[a-z0-9_-]*$`)

// secretValueRe matches values that are credentials by their shape alone.
var secretValueRe = regexp.MustCompile(`^(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})$`)

// reference reports whether a value names a secret rather than holding one:
// an environment or input variable the host or program resolves.
func reference(v string) bool {
	return v == "" || strings.HasPrefix(v, "$") || strings.HasPrefix(v, "%") ||
		strings.HasPrefix(v, "${") || strings.HasPrefix(v, "env:")
}

func auditSecrets(s Server) []Issue {
	var out []Issue
	for i := 0; i < len(s.Args); i++ {
		a := s.Args[i]
		name, val, hasEq := strings.Cut(a, "=")
		switch {
		case secretFlagRe.MatchString(name) && hasEq && !reference(val):
			out = append(out, secretIssue(s, i, fmt.Sprintf("argument %d (%s=…) passes a credential on the command line", i+1, name)))
		case secretFlagRe.MatchString(a) && i+1 < len(s.Args) && !strings.HasPrefix(s.Args[i+1], "-") && !reference(s.Args[i+1]):
			out = append(out, secretIssue(s, i+1, fmt.Sprintf("argument %d, the value of %s, passes a credential on the command line", i+2, a)))
			i++
		case secretValueRe.MatchString(a) || (hasEq && secretValueRe.MatchString(val)):
			out = append(out, secretIssue(s, i, fmt.Sprintf("argument %d has the shape of a credential", i+1)))
		}
	}
	return out
}

func secretIssue(s Server, i int, detail string) Issue {
	return Issue{Server: s.Name, Kind: IssueSecretArg, Line: argLine(s, i),
		Detail: detail + "; every process listing shows it, so pass it in env instead"}
}

// clip bounds text taken from the file. It is the operator's own file, but
// a finding is one line and a command can be long.
func clip(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}

// queryRe matches a query parameter's value, which is where a download URL
// carries a token when it carries one.
var queryRe = regexp.MustCompile(`([?&][^=\s&]+=)[^&\s|"']+`)

// maskQuery replaces every query parameter's value with an ellipsis.
func maskQuery(s string) string { return queryRe.ReplaceAllString(s, "${1}…") }
