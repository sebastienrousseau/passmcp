// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build ignore

// checkinventory writes docs/checks.md from the source, and with -check
// fails when the committed file has drifted.
//
// passmcp publishes a number — "76 checks" — on its own front page. A figure
// a reader is asked to trust, produced by counting by hand, is the same
// class of claim passmcp exists to disbelieve. This reads the call sites.
//
// Every check is created through (*Session).check(id, title). Parsing that
// one call is the whole inventory; a check that does not go through it does
// not exist as far as the report is concerned.
package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type entry struct {
	ID    string
	Title string
	Sites int
	// Family marks a check whose id is built at run time, so one entry
	// here stands for one check per value the run encounters.
	Family bool
	// CanFail marks a check that reaches .fail or .warn somewhere. Those
	// are the checks that can appear in a report's "what to fix first",
	// and so the ones that want remediation guidance written for them.
	// internal/report/remediation_test.go reads this back and fails when
	// one of them has none.
	//
	// markFailable matches every shape this package uses, so the answer is
	// currently exact. A shape it does not know would read false, which
	// leaves a check unguarded rather than failing the build for one that
	// cannot fail — the safe direction for a gate to be wrong in.
	CanFail bool
}

func main() {
	verify := len(os.Args) > 1 && os.Args[1] == "-check"

	// internal/a2a declares its checks the same way, for the A2A command.
	found, err := inventory("internal/probe", "internal/a2a")
	if err != nil {
		fmt.Fprintln(os.Stderr, "check-inventory:", err)
		os.Exit(1)
	}
	if len(found) == 0 {
		fmt.Fprintln(os.Stderr, "check-inventory: no checks found; the parser is looking in the wrong place")
		os.Exit(1)
	}

	want := render(found)
	const path = "docs/checks.md"

	if !verify {
		if err := os.WriteFile(path, want, 0o644); err != nil { //nolint:gosec // documentation, not a secret
			fmt.Fprintln(os.Stderr, "check-inventory:", err)
			os.Exit(1)
		}
		fmt.Printf("check-inventory: wrote %s with %d checks across %d phases\n", path, len(found), phaseCount(found))
		return
	}

	got, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check-inventory: %v\nRun: make checks\n", err)
		os.Exit(1)
	}
	if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(want)) {
		fmt.Fprintf(os.Stderr, "check-inventory: %s is stale — the source declares %d checks.\nRun: make checks\n", path, len(found))
		os.Exit(1)
	}
	if err := verifyPublishedCount(len(found)); err != nil {
		fmt.Fprintf(os.Stderr, "check-inventory: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("check-inventory: %s matches the source (%d checks, %d phases)\n", path, len(found), phaseCount(found))
}

// publishedCountFiles are the places the figure is quoted to a reader
// rather than generated.
//
// docs/checks.md is regenerated, so it cannot drift. These cannot be
// regenerated — they are prose, a marketing headline and an FAQ answer —
// and every one of them was wrong the first time a check was added, which
// is how a tool whose whole argument is "the number is verifiable" ends up
// publishing a number that is not.
var publishedCountFiles = []string{
	"web/content/index.md",
	"web/ssg.toml",
	"docs/index.md",
	"README.md",
	// The shell `passmcp serve` embeds is committed build output that
	// nothing regenerates automatically. It shipped saying 76 checks long
	// after the source said 81, because a rebuild is a thing a person has
	// to remember.
	"internal/web/dist/index.html",
	// The vendored layouts, which is where the figure is actually edited.
	// satellion.com's own layouts moved to satellion.github.io, whose build reads
	// this count from docs/checks.md and fails on a page that disagrees.
	"web/_layouts/app.html",
}

// staleCount matches a published figure in any of the three shapes the
// tree uses: "76 checks"; "76 across 9 phases", the comparison table's
// phrasing, which has no word "checks" after the number and so escaped the
// pattern for sixteen checks' worth of drift; and the site's own
// metric_one_value, the headline number with no word after it at all.
var staleCount = regexp.MustCompile(`(\d+)\s+checks\b|(\d+)\s+across\s+\w+\s+phases\b|metric_one_value:\s*"(\d+)"`)

// verifyPublishedCount fails when any published figure disagrees with the
// source.
func verifyPublishedCount(want int) error {
	var wrong []string
	for _, f := range publishedCountFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		for _, m := range staleCount.FindAllStringSubmatch(string(b), -1) {
			// Whichever alternative matched is the one that is not empty.
			var got string
			for _, g := range m[1:] {
				if g != "" {
					got = g
					break
				}
			}
			n, err := strconv.Atoi(got)
			if err != nil || n == want {
				continue
			}
			wrong = append(wrong, fmt.Sprintf("%s says %d", f, n))
		}
	}
	if len(wrong) > 0 {
		return fmt.Errorf("the source declares %d checks but %s.\nUpdate the published figure; it is the one number a reader checks passmcp against",
			want, strings.Join(wrong, "; "))
	}
	return nil
}

// inventory walks the packages and records every (*Session).check(id, title).
func inventory(dirs ...string) ([]entry, error) {
	fset := token.NewFileSet()
	byID := map[string]*entry{}
	// Filled by markFailable while each file is parsed, and applied to the
	// entries after every file has been seen — a check declared in one file
	// can be failed in another.
	failable := map[string]bool{}

	var files []string
	for _, dir := range dirs {
		matched, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			return nil, err
		}
		files = append(files, matched...)
	}

	// Parsed once and walked three times. The helper pass has to finish
	// before the failable pass starts, because a check opened in one file
	// can be handed to a helper declared in another.
	asts := make([]*ast.File, 0, len(files))
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", f, err)
		}
		asts = append(asts, parsed)
	}
	failingHelpers := map[string]bool{}
	for _, parsed := range asts {
		collectFailingHelpers(parsed, failingHelpers)
	}
	for _, parsed := range asts {
		markFailable(parsed, failable, failingHelpers)
	}

	for _, parsed := range asts {
		ast.Inspect(parsed, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "check" || len(call.Args) != 2 {
				return true
			}
			id, ok1 := literal(call.Args[0])
			title, ok2 := literal(call.Args[1])
			// A computed id is a family of checks, not a missing one:
			// auth.source.<field> emits one per credential source in play.
			// Recording the prefix keeps the inventory honest — dropping it
			// is how a hand count and a generated one disagree, which is
			// exactly what this tool exists to stop.
			if !ok1 {
				prefix, isFamily := literalPrefix(call.Args[0])
				if !isFamily {
					return true
				}
				id = prefix + "*"
				if !ok2 {
					title = ""
				}
				if e, seen := byID[id]; seen {
					e.Sites++
					return true
				}
				byID[id] = &entry{ID: id, Title: title, Sites: 1, Family: true}
				return true
			}
			if e, seen := byID[id]; seen {
				e.Sites++
				if e.Title == "" && ok2 {
					e.Title = title
				}
				return true
			}
			byID[id] = &entry{ID: id, Title: title, Sites: 1}
			return true
		})
	}

	for id := range failable {
		if e, ok := byID[id]; ok {
			e.CanFail = true
		}
	}

	out := make([]entry, 0, len(byID))
	for _, e := range byID {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// literalPrefix pulls the fixed prefix out of `"auth.source." + field`.
func literalPrefix(e ast.Expr) (string, bool) {
	bin, ok := e.(*ast.BinaryExpr)
	if !ok || bin.Op != token.ADD {
		return "", false
	}
	return literal(bin.X)
}

func literal(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

func phaseOf(id string) string {
	if i := strings.IndexByte(id, '.'); i > 0 {
		return id[:i]
	}
	return "other"
}

// phases are the nine diagnostic steps, in the order they run.
//
// It is the same list as probe.Phases, duplicated because this generator
// parses the source rather than importing it — and because it carries a
// build tag, it cannot have a test of its own. What guards the duplication
// is probe's TestInventoryGroupsAreRealPhases, which reads the page this
// writes and fails when a group here is not a phase there.
var phases = []string{"net", "discovery", "auth", "handshake", "protocol", "catalog", "execution", "performance", "resilience"}

// transportGroups are id prefixes that are not phase names.
//
// A stdio check runs inside an existing phase — connectivity or resilience
// — and has no phase of its own. Its id names the transport instead,
// because that is the first thing a reader of the report needs to know
// about it. Counting such a group as a tenth phase would make the figure
// this page publishes disagree with the nine phases passmcp runs, which is
// precisely the drift this generator exists to prevent.
var transportGroups = map[string]string{
	"a2a": "These run only under passmcp a2a check, against an agent that speaks the Agent2Agent " +
		"protocol rather than MCP. They are not a phase of an MCP run: they read the agent's Agent " +
		"Card and make one unauthenticated read, and the id names the protocol because that is the " +
		"first thing a reader needs to know about them.",
	"stdio": "These run only when the server is a program rather than a URL. " +
		"They belong to the connectivity and resilience phases, not to a phase of their own: " +
		"a pipe has no name to resolve and no session to lose, so they take the place of the checks that do.",
	"supply": "These run only when the server is a program, and read the file rather than ask the " +
		"server anything. They belong to the connectivity phase, which is where passmcp establishes what " +
		"it is talking to; the id names what was read because that is what a reader is looking for.",
	"fs": "These run only when the server is a program and --plant-canaries was given. " +
		"They belong to the resilience phase: the decoys are planted before the process starts and " +
		"read back after it ends, so the answer is only complete once the run is. The id names what " +
		"was watched rather than the phase, because that is what a reader is looking for.",
	"egress": "These run only when the server is a program and --watch-egress was given. " +
		"They belong to the resilience phase, at the end of the run, because where a server went " +
		"is only fully answered once it has had the whole run to go there. The id names the " +
		"observation rather than the phase, because that is what a reader is looking for.",
}

func phaseCount(es []entry) int {
	seen := map[string]bool{}
	for _, e := range es {
		p := phaseOf(e.ID)
		if _, isTransport := transportGroups[p]; isTransport {
			continue
		}
		seen[p] = true
	}
	return len(seen)
}

// transportCount counts the checks that belong to a transport group rather
// than to a phase.
func transportCount(es []entry) int {
	n := 0
	for _, e := range es {
		if _, ok := transportGroups[phaseOf(e.ID)]; ok {
			n++
		}
	}
	return n
}

func render(es []entry) []byte {
	var b bytes.Buffer
	// Front matter carries the page's own meta description, so this page
	// does not share the site-wide one with every other manual page.
	b.WriteString("---\n")
	// REUSE-IgnoreStart
	b.WriteString("# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>\n")
	b.WriteString("# SPDX-License-Identifier: GPL-3.0-only\n")
	// REUSE-IgnoreEnd
	b.WriteString("description: >-\n")
	b.WriteString("  Every check passmcp runs against an MCP server, listed by phase with its id and what it asserts. Generated from the source, so it cannot drift.\n")
	b.WriteString("---\n\n")
	b.WriteString("<!-- Generated by scripts/checkinventory. Do not edit; run `make checks`. -->\n\n")
	b.WriteString("# The check inventory\n\n")
	fixed, families := 0, 0
	for _, e := range es {
		if e.Family {
			families++
		} else {
			fixed++
		}
	}
	fmt.Fprintf(&b, "passmcp runs **%d checks** across **%d phases**.\n\n", len(es), phaseCount(es))
	if n := transportCount(es); n > 0 {
		fmt.Fprintf(&b, "%d of them apply only to a server that is a program rather than a URL, and\n"+
			"replace the ones that have no meaning over a pipe. A run reports every check it\n"+
			"did not make, by id and with the reason, rather than leaving it out.\n\n", n)
	}
	if families > 0 {
		fmt.Fprintf(&b, "%d of those are fixed, and %d is a family whose id is built at run time —\n"+
			"one check per value the run encounters, marked `*` below.\n\n", fixed, families)
	}
	b.WriteString("This file is generated from the source: every check is created through\n")
	b.WriteString("`(*Session).check(id, title)`, and this table is those call sites. CI fails\n")
	b.WriteString("when it drifts, so the figure passmcp publishes is the figure it implements.\n\n")
	b.WriteString("A check may be reached from more than one branch — a handshake can fail in\n")
	b.WriteString("several ways and report the same id. The count is of distinct ids, because\n")
	b.WriteString("that is what a reader sees in a report.\n\n")

	order := append([]string{}, phases...)
	for p := range transportGroups {
		order = append(order, p)
	}
	sort.Strings(order[len(phases):])
	grouped := map[string][]entry{}
	for _, e := range es {
		p := phaseOf(e.ID)
		grouped[p] = append(grouped[p], e)
	}
	var rest []string
	for p := range grouped {
		known := false
		for _, o := range order {
			if o == p {
				known = true
				break
			}
		}
		if !known {
			rest = append(rest, p)
		}
	}
	sort.Strings(rest)

	for _, p := range append(order, rest...) {
		in := grouped[p]
		if len(in) == 0 {
			continue
		}
		fmt.Fprintf(&b, "## %s — %d checks\n\n", p, len(in))
		if note, ok := transportGroups[p]; ok {
			b.WriteString(note + "\n\n")
		}
		b.WriteString("| Check | What it looks for |\n|---|---|\n")
		for _, e := range in {
			title := e.Title
			if title == "" {
				title = "_(title computed at run time)_"
			}
			if e.Family {
				title += " — one per value encountered"
			}
			// The anchor is what `doc_url` on every finding points at, so
			// a reader who gets a JSON report six months from now can follow
			// a check id straight to what it asserts. probe.DocURL builds
			// the same slug; checks_doc_test.go asserts the two agree.
			// data-can-fail marks the checks that can reach a fail or a
			// warn. It is an attribute rather than a visible column because
			// a reader does not need it — internal/report does, to assert
			// that every check able to appear in "what to fix first" has
			// remediation guidance written for it.
			fmt.Fprintf(&b, "| <span id=%q data-can-fail=%q></span>`%s` | %s |\n",
				anchor(e.ID), boolAttr(e.CanFail), e.ID, title)
		}
		b.WriteString("\n")
	}
	// markdownlint gates this file like any other. Ending with exactly one
	// newline and no run of blanks keeps the generator's output clean
	// rather than making the linter carry an exception for it.
	return append(bytes.TrimRight(b.Bytes(), "\n"), '\n')
}

// anchor is the HTML id for one check's row in the generated inventory.
//
// Dots are legal in an HTML id but awkward in a URL fragment and in CSS
// selectors, so they become dashes. The "check-" prefix keeps the ids out
// of the way of the heading anchors MkDocs generates from the phase names.
//
// probe.DocURL must produce the same slug. That is asserted, not assumed.
func anchor(id string) string {
	// A computed family is written "auth.source.*". The row documents the
	// family, so the anchor is the family's literal prefix — which is what
	// probe.DocURL resolves a concrete "auth.source.token_env" to.
	id = strings.TrimSuffix(strings.TrimSuffix(id, "*"), ".")
	return "check-" + strings.ReplaceAll(id, ".", "-")
}

// markFailable records every check id that reaches .fail or .warn.
//
// Three shapes are matched, which is every shape this package uses:
//
//	c := s.check(id, title); ...; c.fail(...)     bound, then failed
//	s.check(id, title).fail(...)                  inline
//	helper(s.check(id, title), ...)               opened here, judged there
//
// The third also covers a check bound first and handed on,
//
//	c := s.check(id, title); ...; helper(s, c, ...)
//
// which is how a phase keeps its request order while its verdict lives in
// a named step.
//
// The third needs failingHelpers: a function that calls .fail or .warn on
// one of its own *check parameters is one that can fail whatever it is
// given, so a check handed to it can fail. internal/probe/poison.go is
// built that way — the id has to be a literal at the call site for the
// inventory, and the verdict is shared across five checks, so the two
// cannot sit in the same function.
func markFailable(f *ast.File, out map[string]bool, failing map[string]bool) {
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}
		bound := map[string]string{} // variable -> check id
		ast.Inspect(fn.Body, func(m ast.Node) bool {
			if as, ok := m.(*ast.AssignStmt); ok && len(as.Rhs) == 1 && len(as.Lhs) == 1 {
				if id, ok := checkCallID(as.Rhs[0]); ok {
					if ident, ok := as.Lhs[0].(*ast.Ident); ok {
						bound[ident.Name] = id
					}
				}
			}
			call, ok := m.(*ast.CallExpr)
			if !ok {
				return true
			}
			// helper(s.check(id, title), ...) — a check handed to something
			// that fails its own parameter.
			if name, ok := calleeName(call); ok && failing[name] {
				for _, arg := range call.Args {
					if id, ok := checkCallID(arg); ok {
						out[id] = true
					}
					if ident, ok := arg.(*ast.Ident); ok {
						if id, ok := bound[ident.Name]; ok {
							out[id] = true
						}
					}
				}
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "fail" && sel.Sel.Name != "warn") {
				return true
			}
			switch recv := sel.X.(type) {
			case *ast.Ident: // c.fail(...)
				if id, ok := bound[recv.Name]; ok {
					out[id] = true
				}
			case *ast.CallExpr: // s.check(...).fail(...) or c.ev(...).fail(...)
				if id, ok := checkCallID(recv); ok {
					out[id] = true
					break
				}
				if inner, ok := recv.Fun.(*ast.SelectorExpr); ok {
					if ident, ok := inner.X.(*ast.Ident); ok {
						if id, ok := bound[ident.Name]; ok {
							out[id] = true
						}
					}
				}
			}
			return true
		})
		return true
	})
}

// checkCallID returns the literal id from an s.check("id", "title") call.
func checkCallID(e ast.Expr) (string, bool) {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "check" || len(call.Args) == 0 {
		return "", false
	}
	return literal(call.Args[0])
}

// boolAttr renders a bool for an HTML attribute.
func boolAttr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// collectFailingHelpers finds functions that call .fail or .warn on one of
// their own *check parameters. A check passed to one of those can fail.
func collectFailingHelpers(f *ast.File, out map[string]bool) {
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Type.Params == nil {
			return true
		}
		params := map[string]bool{}
		for _, field := range fn.Type.Params.List {
			star, ok := field.Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			if ident, ok := star.X.(*ast.Ident); !ok || ident.Name != "check" {
				continue
			}
			for _, name := range field.Names {
				params[name.Name] = true
			}
		}
		if len(params) == 0 {
			return true
		}
		ast.Inspect(fn.Body, func(m ast.Node) bool {
			call, ok := m.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "fail" && sel.Sel.Name != "warn") {
				return true
			}
			if ident, ok := sel.X.(*ast.Ident); ok && params[ident.Name] {
				out[fn.Name.Name] = true
			}
			return true
		})
		return true
	})
}

// calleeName returns the name of a plain function call.
func calleeName(call *ast.CallExpr) (string, bool) {
	ident, ok := call.Fun.(*ast.Ident)
	if !ok {
		return "", false
	}
	return ident.Name, true
}
