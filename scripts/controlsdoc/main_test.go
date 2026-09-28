// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// AC: SOC2-06
func TestCommittedCompliancePagesMatchTheirMappings(t *testing.T) {
	stale, err := run("../../docs/compliance", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) > 0 {
		t.Fatalf("stale pages %v; run make controls", stale)
	}
}

// AC: GDPR-06
func TestDriftCheckCatchesAHandEditedPage(t *testing.T) {
	dir := t.TempDir()
	if stale, err := run(dir, false); err != nil || len(stale) != 0 {
		t.Fatalf("write: stale=%v err=%v", stale, err)
	}
	if stale, err := run(dir, true); err != nil || len(stale) != 0 {
		t.Fatalf("fresh pages reported stale: %v %v", stale, err)
	}
	page := filepath.Join(dir, "gdpr.md")
	if err := os.WriteFile(page, []byte("hand edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "soc2.md")); err != nil {
		t.Fatal(err)
	}
	stale, err := run(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) != 2 {
		t.Fatalf("stale = %v, want the edited gdpr page and the missing soc2 page", stale)
	}
	var out, errs bytes.Buffer
	if code := cli([]string{"-check", "-dir", dir}, &out, &errs); code != 1 || !strings.Contains(errs.String(), "gdpr.md is stale") {
		t.Fatalf("cli -check on a stale dir: code=%d stderr=%q", code, errs.String())
	}
	if code := cli([]string{"-dir", dir}, &out, &errs); code != 0 {
		t.Fatalf("cli write: code=%d stderr=%q", code, errs.String())
	}
	out.Reset()
	if code := cli([]string{"-check", "-dir", dir}, &out, &errs); code != 0 || !strings.Contains(out.String(), "matches its mapping") {
		t.Fatalf("cli -check after write: code=%d stdout=%q", code, out.String())
	}
	if code := cli([]string{"-nope"}, &out, &errs); code != 2 {
		t.Fatalf("an unknown flag exited %d", code)
	}
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if code := cli([]string{"-dir", filepath.Join(blocker, "sub")}, &out, &errs); code != 1 {
		t.Fatalf("an unwritable dir exited %d", code)
	}
}
