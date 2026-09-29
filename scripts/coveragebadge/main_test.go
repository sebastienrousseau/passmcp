// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeProfile puts a cover profile in a temporary directory.
func writeProfile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "coverage.out")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunWritesTheEndpointDocument(t *testing.T) {
	// Six statements, four covered; the duplicate block is covered by the
	// second test binary and counted once; the excluded file is not counted.
	p := writeProfile(t, "mode: set\n"+
		"m/a.go:1.1,2.2 2 1\n"+
		"m/a.go:3.1,4.2 2 0\n"+
		"m/a.go:3.1,4.2 2 1\n"+
		"m/b.go:1.1,2.2 2 0\n"+
		"\n"+
		"m/cmd/main.go:1.1,2.2 5 0\n")
	var out, errw bytes.Buffer
	if code := run([]string{"-profile", p, "-exclude", "/cmd/, "}, &out, &errw); code != 0 {
		t.Fatalf("exit %d: %s", code, errw.String())
	}
	var got badge
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := badge{SchemaVersion: 1, Label: "coverage", Message: "66.6%", Color: "red"}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if errw.Len() != 0 {
		t.Errorf("diagnostics on success: %q", errw.String())
	}
}

func TestRunRefusesBadInvocations(t *testing.T) {
	cases := map[string]struct {
		args []string
		code int
		msg  string
	}{
		"no profile":      {nil, 2, "-profile is required"},
		"unknown flag":    {[]string{"-nope"}, 2, "flag provided but not defined"},
		"missing file":    {[]string{"-profile", filepath.Join(t.TempDir(), "absent")}, 1, "no such file"},
		"malformed block": {[]string{"-profile", writeProfile(t, "mode: set\nnot a block\n")}, 1, "line 2"},
		"bad statements":  {[]string{"-profile", writeProfile(t, "a.go:1.1,2.2 x 1\n")}, 1, "bad statement count"},
		"bad count":       {[]string{"-profile", writeProfile(t, "a.go:1.1,2.2 1 -1\n")}, 1, "bad execution count"},
		"empty profile":   {[]string{"-profile", writeProfile(t, "mode: set\n")}, 1, "no statements"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var out, errw bytes.Buffer
			if code := run(tc.args, &out, &errw); code != tc.code {
				t.Fatalf("exit %d, want %d", code, tc.code)
			}
			if !strings.Contains(errw.String(), tc.msg) {
				t.Errorf("stderr %q does not mention %q", errw.String(), tc.msg)
			}
			if out.Len() != 0 {
				t.Errorf("stdout carries %q on failure", out.String())
			}
		})
	}
}

func TestBadgeColourBands(t *testing.T) {
	cases := []struct {
		pct   float64
		msg   string
		color string
	}{
		{100, "100.0%", "brightgreen"},
		{90, "90.0%", "brightgreen"},
		{89.99, "89.9%", "green"},
		{85, "85.0%", "green"},
		// Truncated, not rounded: the badge never claims the gate early.
		{84.96, "84.9%", "yellow"},
		{70, "70.0%", "yellow"},
		{69.9, "69.9%", "red"},
		{0, "0.0%", "red"},
	}
	for _, tc := range cases {
		got := badgeFor(tc.pct)
		if got.Message != tc.msg || got.Color != tc.color {
			t.Errorf("badgeFor(%v) = %s %s, want %s %s", tc.pct, got.Message, got.Color, tc.msg, tc.color)
		}
	}
}
