// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package trace

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Citation is one test that cites one criterion.
type Citation struct {
	ID      string `json:"id"`
	Package string `json:"package"` // directory, relative to the scanned root, as ./dir
	Test    string `json:"test"`    // the test function's name
	File    string `json:"file"`    // relative to the scanned root
	Line    int    `json:"line"`
}

// Malformed is an `// AC:` comment that names something that is not a
// criterion ID. It is reported rather than ignored: a typo in a citation
// would otherwise leave a criterion looking untested, or tested, silently.
type Malformed struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

var acComment = regexp.MustCompile(`^//\s*AC:\s*(.*)$`)

// skipDir names directories the scan never enters. testdata holds fixtures,
// including test files whose citations are about this package's own tests,
// not about passmcp; the rest are not source.
var skipDir = map[string]bool{"testdata": true, "vendor": true, "node_modules": true, ".git": true, ".claude": true}

// Scan walks root for *_test.go files and returns every citation found on a
// test or fuzz function's doc comment, sorted by ID then location.
func Scan(root string) ([]Citation, []Malformed, error) {
	var cits []Citation
	var bad []Malformed
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (skipDir[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		c, m, err := scanFile(root, path)
		cits = append(cits, c...)
		bad = append(bad, m...)
		return err
	})
	sort.Slice(cits, func(i, j int) bool {
		a, b := cits[i], cits[j]
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	return cits, bad, err
}

// scanFile parses one test file and collects the citations on its test and
// fuzz functions.
func scanFile(root, path string) ([]Citation, []Malformed, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, nil, err
	}
	rel, _ := filepath.Rel(root, path)
	rel = filepath.ToSlash(rel)
	pkg := "./" + filepath.ToSlash(filepath.Dir(rel))
	if filepath.Dir(rel) == "." {
		pkg = "."
	}
	var cits []Citation
	var bad []Malformed
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Doc == nil || fn.Recv != nil || !isTestName(fn.Name.Name) {
			continue
		}
		for _, c := range fn.Doc.List {
			m := acComment.FindStringSubmatch(c.Text)
			if m == nil {
				continue
			}
			line := fset.Position(c.Pos()).Line
			ids, rest := parseIDs(m[1])
			for _, id := range ids {
				cits = append(cits, Citation{ID: id, Package: pkg, Test: fn.Name.Name, File: rel, Line: line})
			}
			for _, r := range rest {
				bad = append(bad, Malformed{File: rel, Line: line, Text: r})
			}
		}
	}
	return cits, bad, nil
}

// isTestName reports whether a function is one `go test -run` selects: a
// test or a fuzz target.
func isTestName(name string) bool {
	return strings.HasPrefix(name, "Test") || strings.HasPrefix(name, "Fuzz")
}

// parseIDs splits an `AC:` list on commas and spaces into criterion IDs and
// whatever is not one.
func parseIDs(list string) (ids, rest []string) {
	for _, tok := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if IDPattern.MatchString(tok) {
			ids = append(ids, tok)
		} else {
			rest = append(rest, tok)
		}
	}
	if len(ids) == 0 && len(rest) == 0 {
		rest = append(rest, "(empty)")
	}
	return ids, rest
}
