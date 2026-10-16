// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"os"
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
