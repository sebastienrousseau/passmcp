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

// AC: ISO-05
func TestSoACitesOnlyFilesThatExist(t *testing.T) {
	var out bytes.Buffer
	if err := run(&out, "../../docs/compliance/iso27001-soa.md", "../.."); err != nil {
		t.Fatalf("the committed Statement of Applicability fails its own check: %v", err)
	}
	if !strings.Contains(out.String(), "cited files exist") {
		t.Errorf("output = %q", out.String())
	}
	cited, err := evidence("../../docs/compliance/iso27001-soa.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"SECURITY.md", ".goreleaser.yaml", ".github/workflows/ci.yml"} {
		if !contains(cited, want) {
			t.Errorf("evidence %v does not include %s", cited, want)
		}
	}
}

// AC: ISO-05
func TestSoACheckFailsOnAMissingFile(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "SECURITY.md"), "policy")
	soa := filepath.Join(dir, "soa.md")
	write(t, soa, "# SoA\n\n| Control | Applies | How | Evidence |\n|---|---|---|---|\n"+
		"| A.5.24 | Yes | Disclosure. | `SECURITY.md` |\n"+
		"| A.8.24 | Yes | Signing, see `docs/signing.md` in prose. | `docs/gone.md`, `SECURITY.md` |\n")
	err := run(&bytes.Buffer{}, soa, dir)
	if err == nil || !strings.Contains(err.Error(), "docs/gone.md") {
		t.Fatalf("err = %v, want it to name docs/gone.md", err)
	}
	if strings.Contains(err.Error(), "docs/signing.md") {
		t.Errorf("a path in the prose column was treated as evidence: %v", err)
	}
}

func TestSoACheckRejectsATableWithoutEvidence(t *testing.T) {
	dir := t.TempDir()
	soa := filepath.Join(dir, "soa.md")
	write(t, soa, "# SoA\n\n| Control | Applies |\n|---|---|\n| A.7.1 | No |\n")
	if err := run(&bytes.Buffer{}, soa, dir); err == nil || !strings.Contains(err.Error(), "cites no evidence") {
		t.Fatalf("err = %v", err)
	}
	if err := run(&bytes.Buffer{}, filepath.Join(dir, "absent.md"), dir); err == nil {
		t.Fatal("a missing SoA passed")
	}
}

func write(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
