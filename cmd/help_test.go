// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

func TestRenderHelp(t *testing.T) {
	var b bytes.Buffer
	renderHelp(&b, rootCmd, 80)
	out := b.String()
	for _, want := range []string{"passmcp", "USAGE", "EXAMPLES", "COMMANDS", "check", "FLAGS", "--log-level", "ENVIRONMENT", "--help"} {
		if !strings.Contains(out, want) {
			t.Errorf("root help lacks %q", want)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if lipgloss.Width(line) > 80 {
			t.Errorf("help line wider than 80: %q", line)
		}
	}
	b.Reset()
	renderHelp(&b, checkCmd, 90)
	out = b.String()
	for _, want := range []string{"passmcp check", "FLAGS", "--allow-destructive", "(default 2)", "GLOBAL FLAGS"} {
		if !strings.Contains(out, want) {
			t.Errorf("check help lacks %q", want)
		}
	}
	t.Setenv("PASSMCP_SHOW_LOGO", "0")
	b.Reset()
	renderHelp(&b, rootCmd, 80)
	plainOut := ansiRE.ReplaceAllString(b.String(), "")
	if strings.Contains(plainOut, "⣿") || !strings.Contains(plainOut, "  passmcp\n") {
		t.Errorf("logo off must render the plain title line:\n%s", plainOut)
	}
	// piped: cobra's plain help is used
	if out, code := run(t, "--help"); code != 0 || !strings.Contains(out, "Available Commands:") {
		t.Errorf("piped help must stay plain: %d %q", code, out)
	}
}

var ansiRE = regexp.MustCompile("\x1b\\[[0-9;]*m")

// Help text becomes a manpage, and groff rejects a byte above 127 as an
// invalid input character. That gate lives in CI and needs groff; this one
// needs nothing, so the em dash that looks right in a terminal fails here
// rather than after a push.
//
// Runtime strings are exempt: only Short and Long are rendered by
// scripts/gen_docs.go.
func TestHelpTextIsASCII(t *testing.T) {
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, f := range []struct{ what, text string }{
			{"Short", c.Short},
			{"Long", c.Long},
			{"Example", c.Example},
		} {
			for i, r := range f.text {
				if r > 127 {
					t.Errorf("%s %s contains %q at byte %d: groff reads it as an invalid input character.\n"+
						"Use ASCII in help text; an em dash or a typographic quote fails the manpage build.",
						c.CommandPath(), f.what, r, i)
					break
				}
			}
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(rootCmd)
}

// Every flag's usage string ends up in the manpage too.
func TestFlagUsageIsASCII(t *testing.T) {
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		check := func(f *pflagFlag) {
			for _, r := range f.Usage {
				if r > 127 {
					t.Errorf("%s --%s usage contains %q: groff reads it as an invalid input character", c.CommandPath(), f.Name, r)
					return
				}
			}
		}
		c.Flags().VisitAll(check)
		c.PersistentFlags().VisitAll(check)
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(rootCmd)
}
