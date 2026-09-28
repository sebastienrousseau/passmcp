// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func testCmd() *cobra.Command {
	c := &cobra.Command{Use: "check"}
	c.Flags().Float64("rps", 2, "rate")
	c.Flags().Bool("allow-mutations", false, "m")
	c.Flags().StringSlice("phases", nil, "p")
	c.Flags().String("auth", "auto", "a")
	c.Flags().Duration("timeout", 0, "t")
	return c
}

func TestApplyPrecedenceAndUnknown(t *testing.T) {
	c := testCmd()
	_ = c.Flags().Set("rps", "9") // explicit flag wins
	applied, err := Apply(c, map[string]any{"rps": 4.0, "allow-mutations": true, "phases": []any{"net", "auth"}, "concurrency": 3.0}, "defaults", map[string]bool{"concurrency": true})
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := c.Flags().GetFloat64("rps"); v != 9 {
		t.Errorf("explicit flag overridden: %v", v)
	}
	if v, _ := c.Flags().GetBool("allow-mutations"); !v {
		t.Error("bool not applied")
	}
	if v, _ := c.Flags().GetStringSlice("phases"); len(v) != 2 || v[1] != "auth" {
		t.Errorf("slice = %v", v)
	}
	if len(applied) != 2 {
		t.Errorf("applied = %v", applied)
	}
	if _, err := Apply(c, map[string]any{"rsp": 1.0}, "defaults", nil); err == nil || !strings.Contains(err.Error(), `unknown setting "rsp"`) {
		t.Errorf("typo not rejected: %v", err)
	}
	if _, err := Apply(c, map[string]any{"auth": nil}, "defaults", nil); err == nil {
		t.Error("null must be rejected")
	}
}

func TestLoadTemplateRoundTrip(t *testing.T) {
	c := testCmd()
	tpl := Template(c)
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(tpl), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := Load(p)
	if err != nil {
		t.Fatalf("template does not load: %v\n%s", err, tpl)
	}
	if len(f.Defaults) != 0 || len(f.Profiles) != 0 {
		t.Errorf("template should be empty when commented: %+v", f)
	}
	// Uncomment the value lines: each must be valid JSON in context.
	var lines []string
	for _, l := range strings.Split(tpl, "\n") {
		tr := strings.TrimSpace(l)
		if strings.HasPrefix(tr, `// "`) && !strings.Contains(tr, "endpoint") && !strings.HasPrefix(tr, `// "prod"`) && !strings.HasPrefix(tr, `// "settings"`) {
			l = strings.Replace(l, "// ", "", 1)
		}
		lines = append(lines, l)
	}
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err = Load(p)
	if err != nil {
		t.Fatalf("uncommented template invalid: %v\n%s", err, strings.Join(lines, "\n"))
	}
	if f.Defaults["rps"] != 2.0 || f.Defaults["auth"] != "auto" {
		t.Errorf("defaults = %v", f.Defaults)
	}
	if _, err := Load(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("missing explicit file must error")
	}
	if err := os.WriteFile(p, []byte(`{"profiles":{"x":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Error("profile without endpoint must error")
	}
}

func TestLoadOptionalMissingDefault(t *testing.T) {
	t.Setenv("PASSMCP_CONFIG", filepath.Join(t.TempDir(), "nope.json"))
	f, _, err := LoadOptional("")
	if err != nil || len(f.Defaults) != 0 {
		t.Errorf("missing default file should be empty: %v", err)
	}
}
