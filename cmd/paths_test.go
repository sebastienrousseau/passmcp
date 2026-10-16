// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"os"
	"runtime"
	"testing"
)

// With no home directory there is no default config file, and the --config
// help must say so rather than name a path relative to wherever passmcp
// happens to run.
func TestDefaultConfigHelpWithoutAHomeDirectory(t *testing.T) {
	t.Setenv("PASSMCP_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	t.Setenv("home", "")
	if _, err := os.UserHomeDir(); err == nil {
		t.Skip("this platform reports a home directory without the variables")
	}
	if got := defaultConfigHelp(); got != "none: no home directory" {
		t.Errorf("defaultConfigHelp() = %q", got)
	}
}

// /Users/sebastian is not under /Users/seb. Shortening by string prefix
// alone showed it as ~astian.
func TestTildePathNeedsASeparatorBoundary(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		t.Skip("HOME is not where this platform reads the home directory")
	}
	t.Setenv("HOME", "/Users/seb")
	for p, want := range map[string]string{
		"/Users/sebastian/x": "/Users/sebastian/x",
		"/Users/seb/x":       "~/x",
	} {
		if got := tildePath(p); got != want {
			t.Errorf("tildePath(%q) = %q, want %q", p, got, want)
		}
	}
}

// A path is shortened only when it is the home directory or lies under it.
// On Windows the comparison ignores case and accepts either separator, as
// the filesystem does.
func TestTildeUnder(t *testing.T) {
	for _, tc := range []struct {
		name, p, home string
		windows       bool
		want          string
	}{
		{"under home", "/Users/seb/.config/x", "/Users/seb", false, "~/.config/x"},
		{"home itself", "/Users/seb", "/Users/seb", false, "~"},
		{"sibling sharing a prefix", "/Users/sebastian/x", "/Users/seb", false, "/Users/sebastian/x"},
		{"home with a trailing slash", "/Users/seb/x", "/Users/seb/", false, "~/x"},
		{"elsewhere", "/etc/passmcp", "/Users/seb", false, "/etc/passmcp"},
		{"unix is case-sensitive", "/users/seb/x", "/Users/seb", false, "/users/seb/x"},
		{"root home shortens nothing", "/x", "/", false, "/x"},
		{"empty home", "/x", "", false, "/x"},
		{"windows", `C:\Users\Seb\AppData\x`, `C:\Users\Seb`, true, `~\AppData\x`},
		{"windows ignores case", `c:\users\seb\x`, `C:\Users\Seb`, true, `~\x`},
		{"windows sibling", `C:\Users\Sebastian\x`, `C:\Users\Seb`, true, `C:\Users\Sebastian\x`},
		{"windows forward slash", `C:\Users\Seb/x`, `C:\Users\Seb`, true, `~/x`},
		{"backslash is a name on unix", `/Users/seb\x`, "/Users/seb", false, `/Users/seb\x`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tildeUnder(tc.p, tc.home, tc.windows); got != tc.want {
				t.Errorf("tildeUnder(%q, %q, %v) = %q, want %q", tc.p, tc.home, tc.windows, got, tc.want)
			}
		})
	}
}
