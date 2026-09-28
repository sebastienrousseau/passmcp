// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultPathPrecedence(t *testing.T) {
	t.Setenv("PASSMCP_CONFIG", "/explicit/config.json")
	if DefaultPath() != "/explicit/config.json" {
		t.Error("PASSMCP_CONFIG must win")
	}
	t.Setenv("PASSMCP_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	if DefaultPath() != filepath.Join("/xdg", "passmcp", "config.json") {
		t.Errorf("xdg path = %s", DefaultPath())
	}
	t.Setenv("XDG_CONFIG_HOME", "")
	home, _ := os.UserHomeDir()
	if DefaultPath() != filepath.Join(home, ".config", "passmcp", "config.json") {
		t.Errorf("home path = %s", DefaultPath())
	}
	t.Setenv("HOME", "")
	if !strings.HasSuffix(DefaultPath(), filepath.Join(".config", "passmcp", "config.json")) {
		t.Errorf("fallback path = %s", DefaultPath())
	}
}

func TestLoadOptionalBrokenAndExplicit(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	if err := os.WriteFile(p, []byte(`{"defaults":{"rps":1}, "unknown_top": 1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOptional(p); err == nil {
		t.Error("unknown top-level field must fail")
	}
	if _, path, err := LoadOptional(filepath.Join(dir, "missing.json")); err == nil || path == "" {
		t.Error("explicit missing file must fail")
	}
	t.Setenv("PASSMCP_CONFIG", p)
	_ = os.WriteFile(p, []byte(`{"defaults":{"rps":1}}`), 0o600)
	f, _, err := LoadOptional("")
	if err != nil || f.Defaults["rps"] != 1.0 {
		t.Errorf("default path load: %v %v", err, f)
	}
	_ = os.WriteFile(p, []byte(`{broken`), 0o600)
	if _, _, err := LoadOptional(""); err == nil {
		t.Error("broken default file must fail")
	}
}

func TestToStringAndApplyErrors(t *testing.T) {
	for v, want := range map[any]string{true: "true", 1.5: "1.5", 2.0: "2", "s": "s"} {
		if got, err := toString(v); err != nil || got != want {
			t.Errorf("toString(%v) = %q %v", v, got, err)
		}
	}
	if got, err := toString([]any{"a", 1.0}); err != nil || got != "a,1" {
		t.Errorf("slice = %q %v", got, err)
	}
	if _, err := toString([]any{nil}); err == nil {
		t.Error("nested null")
	}
	if _, err := toString(map[string]any{}); err == nil {
		t.Error("object must be unsupported")
	}
	c := testCmd()
	if _, err := Apply(c, map[string]any{"rps": "not-a-number"}, "defaults", nil); err == nil {
		t.Error("flag Set error must propagate")
	}
	if _, err := Apply(c, map[string]any{"phases": map[string]any{}}, "defaults", nil); err == nil {
		t.Error("unsupported value type")
	}
}

func TestStripCommentsKeepsInlineCode(t *testing.T) {
	in := "{\n  // comment\n  \"a\": \"http://x\"\n}"
	out := stripComments(in)
	if strings.Contains(out, "comment") || !strings.Contains(out, "http://x") {
		t.Errorf("stripComments = %q", out)
	}
}
