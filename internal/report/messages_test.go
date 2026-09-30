// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"bytes"
	"flag"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"satellion.com/passmcp/internal/probe"
)

var updateGolden = flag.Bool("update", false, "rewrite the Markdown golden files")

// goldenReports are the fixtures whose Markdown rendering is pinned byte
// for byte. Between them they reach every fixed string the renderer
// writes: the full run, one with remediation guidance, and one that was
// stopped before it could be scored.
func goldenReports() map[string]*Report {
	full := fullReport()
	full.Started = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	full.Execution.Tools = append(full.Execution.Tools, probe.ToolResult{Name: "plain", Executed: true, OK: true, ContentTypes: []string{"text"}})

	guided := guidedReport()
	guided.Started = full.Started
	guided.Score = ComputeScore(guided.Phases)

	blocked := &Report{
		Passmcp: Meta{Version: "t"},
		Target:  Target{Endpoint: "https://x/mcp"},
		Started: full.Started,
		Blocked: "credentials | rejected",
		Auth:    AuthSummary{Mode: "none"},
		Phases: []probe.PhaseResult{
			{Name: "net", Title: "Network", Status: probe.Pass},
			{Name: "auth", Title: "Auth", Status: probe.Skip, Skipped: "blocked"},
		},
	}
	blocked.Score = ComputeScore(blocked.Phases)
	return map[string]*Report{"full": full, "guided": guided, "blocked": blocked}
}

// TestMarkdownGolden pins the Markdown output byte for byte, so moving
// its fixed strings into the catalogue changes nothing a reader sees.
// Run with -update to rewrite the files after a deliberate change.
func TestMarkdownGolden(t *testing.T) {
	for name, r := range goldenReports() {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			Markdown(&buf, r)
			path := filepath.Join("testdata", "markdown_"+name+".golden")
			if *updateGolden {
				if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading %s: %v (run with -update to create it)", path, err)
			}
			if !bytes.Equal(buf.Bytes(), want) {
				t.Errorf("Markdown output for %q differs from %s\n--- got ---\n%s", name, path, buf.String())
			}
		})
	}
}

// idArgs names the catalogue lookups and where their IDs are: the position
// of the first, and whether every argument after it is one too.
var idArgs = map[string]struct {
	first    int
	variadic bool
}{
	"mdText":      {0, false},
	"mdRow":       {1, false},
	"mdTableHead": {1, true},
}

// catalogueRefs reads Go source and returns every message ID it passes to
// a catalogue lookup, and the position of every lookup whose ID is not a
// string literal. A computed ID cannot be checked, so outside the lookups
// themselves it is reported rather than trusted.
func catalogueRefs(t *testing.T, name string, src any) (ids, dynamic []string) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		_, forwarding := idArgs[fn.Name.Name]
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			got, bad := callIDs(call)
			ids = append(ids, got...)
			if bad && !forwarding {
				dynamic = append(dynamic, fset.Position(call.Pos()).String())
			}
			return true
		})
	}
	return ids, dynamic
}

// callIDs returns the literal IDs one call passes to a catalogue lookup,
// and whether any ID argument was not a string literal.
func callIDs(call *ast.CallExpr) (ids []string, dynamic bool) {
	fn, ok := call.Fun.(*ast.Ident)
	if !ok {
		return nil, false
	}
	pos, ok := idArgs[fn.Name]
	if !ok {
		return nil, false
	}
	args := call.Args[min(pos.first, len(call.Args)):]
	if !pos.variadic {
		args = args[:min(1, len(args))]
	}
	for _, arg := range args {
		lit, ok := arg.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			dynamic = true
			continue
		}
		id, err := strconv.Unquote(lit.Value)
		if err != nil {
			dynamic = true
			continue
		}
		ids = append(ids, id)
	}
	return ids, dynamic
}

// undefinedIDs returns the IDs that the catalogue does not define.
func undefinedIDs(ids []string) []string {
	var out []string
	for _, id := range ids {
		if _, ok := mdMessages[id]; !ok {
			out = append(out, id)
		}
	}
	return out
}

// TestMarkdownMessageIDsAreDefined parses the Markdown renderer and fails
// if it asks the catalogue for an ID the catalogue does not define, if it
// computes an ID instead of naming one, or if the catalogue holds an entry
// nothing uses.
func TestMarkdownMessageIDsAreDefined(t *testing.T) {
	used := map[string]bool{}
	for _, name := range []string{"render_md.go", "messages.go"} {
		ids, dynamic := catalogueRefs(t, name, nil)
		if bad := undefinedIDs(ids); len(bad) > 0 {
			t.Errorf("%s uses message IDs the catalogue does not define: %q", name, bad)
		}
		if len(dynamic) > 0 {
			t.Errorf("%s computes message IDs, which cannot be checked: %v", name, dynamic)
		}
		for _, id := range ids {
			used[id] = true
		}
	}
	if len(used) == 0 {
		t.Fatal("no message IDs found; the renderer or this test changed shape")
	}
	for id := range mdMessages {
		if !used[id] {
			t.Errorf("catalogue entry %q is not used by the renderer", id)
		}
	}
}

// TestCatalogueCheckCatchesUndefinedIDs proves the check above can fail:
// a renderer that asks for an undefined ID, or computes one, is reported.
func TestCatalogueCheckCatchesUndefinedIDs(t *testing.T) {
	src := `package report
func f(p mdPrinter, id string) {
	p("%s", mdText("heading.nope"))
	mdRow(p, "title", "v")
	mdTableHead(p, "perf.p50", "col.nope")
	mdText(id)
	other("heading.ignored")
}`
	ids, dynamic := catalogueRefs(t, "synthetic.go", src)
	if got := undefinedIDs(ids); !slices.Equal(got, []string{"heading.nope", "col.nope"}) {
		t.Errorf("undefined IDs = %q, want heading.nope and col.nope", got)
	}
	if len(dynamic) != 1 {
		t.Errorf("computed IDs = %v, want the one mdText(id)", dynamic)
	}
	if got := mdText("heading.nope"); got != "heading.nope" {
		t.Errorf("an undefined ID renders as %q, want the ID itself", got)
	}
}
