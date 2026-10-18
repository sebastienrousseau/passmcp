// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"regexp"
	"strings"
	"testing"

	"satellion.com/passmcp/internal/probe"
)

// tagPattern matches the markup of a document: every real tag. Server data
// is escaped, so a payload such as "<img onerror=...>" arrives as &lt;img
// and never matches; what matches is what the template itself emitted.
var tagPattern = regexp.MustCompile(`<[a-zA-Z][^>]*>`)

// inlineAttr matches an attribute a strict Content-Security-Policy refuses
// to honour without 'unsafe-inline': a style attribute or an event handler.
var inlineAttr = regexp.MustCompile(`(?i)\s(style|on[a-z]+)\s*=`)

// A page served under a policy without 'unsafe-inline' renders only what it
// loads from files. With a linked stylesheet the document must carry no
// <style>, no <script>, no style attribute and no event handler, or the
// browser blocks it and the reader gets a page without its layout.
func TestHTMLLinkedStylesheetHasNothingInline(t *testing.T) {
	r := htmlFixture()
	// Hostile text in every position, so a payload that broke out of its
	// escaping would show up here as a tag with an inline attribute.
	for _, p := range []string{`<style>body{display:none}</style>`, `"><b style="x" onclick="alert(1)">`, `<script>alert(1)</script>`} {
		r.Catalog.Tools = append(r.Catalog.Tools, ToolSummary{Name: p, Description: p, Annotated: true})
		r.Phases[0].Findings = append(r.Phases[0].Findings, probe.Finding{ID: "hostile", Title: p, Status: probe.Warn, Detail: p, Advice: p})
	}
	r.Perf = &probe.PerfResult{Tools: []probe.ToolPerf{{Name: "lookup"}}}
	var b strings.Builder
	if err := HTML(&b, r, HTMLOptions{Verbose: true, Stylesheet: StylesheetFile}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, `<link rel="stylesheet" href="report.css">`) {
		t.Error("the document does not link report.css")
	}
	tags := tagPattern.FindAllString(out, -1)
	if len(tags) < 50 {
		t.Fatalf("found %d tags; the pattern is not seeing the document", len(tags))
	}
	for _, tag := range tags {
		lower := strings.ToLower(tag)
		if strings.HasPrefix(lower, "<style") || strings.HasPrefix(lower, "<script") {
			t.Errorf("inline element in the linked document: %s", tag)
		}
		if inlineAttr.MatchString(tag) {
			t.Errorf("inline attribute in the linked document: %s", tag)
		}
	}
}

// The default stays one self-contained file, carrying exactly the
// stylesheet the linked form writes beside it, so the two cannot drift.
func TestHTMLDefaultInlinesTheSameStylesheet(t *testing.T) {
	var b strings.Builder
	if err := HTML(&b, htmlFixture(), HTMLOptions{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "<style>"+Stylesheet()+"</style>") {
		t.Error("the single-file document does not inline Stylesheet() byte for byte")
	}
	if strings.Contains(out, "<link rel=\"stylesheet\"") {
		t.Error("the single-file document links a stylesheet it does not ship with")
	}
	if strings.TrimSpace(Stylesheet()) == "" {
		t.Error("the stylesheet is empty")
	}
}
