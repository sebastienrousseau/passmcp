// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// check --output html --report-dir DIR --html-assets prints a page that
// links report.css and leaves the stylesheet in DIR, so the page saved
// into DIR renders under a Content-Security-Policy refusing inline style.
func TestCheckHTMLAssets(t *testing.T) {
	f := newFakeServer(t)
	f.open = true
	dir := t.TempDir()
	args := append([]string{"check", f.srv.URL + "/mcp", "--phases", "net,handshake",
		"--output", "html", "--report-dir", dir, "--html-assets"}, fastFlags()...)
	out, _ := run(t, args...)
	if !strings.Contains(out, `<link rel="stylesheet" href="report.css">`) || strings.Contains(out, "<style") {
		t.Errorf("the stdout page does not link its stylesheet:\n%.400s", out)
	}
	for _, name := range []string{"report.css", "report.html"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	// Refused before the run: no page that links a file nobody wrote. The
	// message is asserted in the engine, where the refusal lives.
	if out, code := run(t, "check", f.srv.URL+"/mcp", "--output", "html", "--html-assets"); code != 1 || out != "" {
		t.Errorf("--html-assets without --report-dir was accepted (exit %d):\n%.400s", code, out)
	}
}
