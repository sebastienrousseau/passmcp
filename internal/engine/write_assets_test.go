// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"satellion.com/passmcp/internal/report"
)

// --html-assets puts the stylesheet beside the HTML report and has both the
// saved report.html and the stdout rendering link it, so a directory served
// under a strict Content-Security-Policy renders with its layout.
func TestWriteDirHTMLAssets(t *testing.T) {
	srv := demoServer(t)
	spec := demoSpec(srv)
	spec.Phases.Only = []string{"net", "handshake"}
	dir := filepath.Join(t.TempDir(), "out")
	spec.Output.ReportDir = dir
	spec.Output.HTMLAssets = true
	spec.Output.Format = FormatHTML
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}

	res := Run(context.Background(), spec, nil)
	if res.Report == nil {
		t.Fatalf("no report: %v", res.Err)
	}
	files, err := res.WriteDir(spec, "test")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(files, filepath.Join(dir, report.StylesheetFile)) {
		t.Errorf("report.css is not among the files written: %v", files)
	}
	css, err := os.ReadFile(filepath.Join(dir, report.StylesheetFile))
	if err != nil || string(css) != report.Stylesheet() {
		t.Errorf("report.css is not the report's stylesheet (err %v)", err)
	}
	page, _ := os.ReadFile(filepath.Join(dir, "report.html"))
	assertLinked(t, "report.html", string(page))

	var stdout strings.Builder
	if err := res.Render(&stdout, spec, 80); err != nil {
		t.Fatal(err)
	}
	assertLinked(t, "the stdout rendering", stdout.String())

	// Without the flag nothing changes: one self-contained file, no
	// stylesheet beside it.
	plain := spec
	plain.Output.HTMLAssets = false
	plain.Output.ReportDir = filepath.Join(t.TempDir(), "plain")
	if _, err := res.WriteDir(plain, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(plain.Output.ReportDir, report.StylesheetFile)); !os.IsNotExist(err) {
		t.Errorf("report.css written without --html-assets: %v", err)
	}
	single, _ := os.ReadFile(filepath.Join(plain.Output.ReportDir, "report.html"))
	if !strings.Contains(string(single), "<style>") {
		t.Error("the default report.html no longer carries its stylesheet")
	}
}

// The stylesheet has to land somewhere the page can reach, and stdout holds
// one document, so the flag without a report directory is refused rather
// than producing a page that links a file nobody wrote.
func TestValidateHTMLAssetsNeedsReportDir(t *testing.T) {
	spec := RunSpec{Target: TargetSpec{Endpoint: "https://x/mcp"}}.WithDefaults()
	spec.Output.HTMLAssets = true
	err := spec.Validate()
	if err == nil || !strings.Contains(err.Error(), "--report-dir") {
		t.Fatalf("want a refusal naming --report-dir, got %v", err)
	}
	spec.Output.ReportDir = t.TempDir()
	if err := spec.Validate(); err != nil {
		t.Errorf("with --report-dir it is valid: %v", err)
	}
}

func assertLinked(t *testing.T, what, page string) {
	t.Helper()
	if !strings.Contains(page, `<link rel="stylesheet" href="report.css">`) {
		t.Errorf("%s does not link report.css", what)
	}
	if strings.Contains(page, "<style") {
		t.Errorf("%s still carries an inline <style>", what)
	}
}
