// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"context"
	"encoding/json"
	"os"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

func jsonOrString(v string) any {
	var out any
	if err := json.Unmarshal([]byte(v), &out); err == nil {
		return out
	}
	return v
}

// stdoutIsTTY is a variable so tests can drive the terminal paths
// (progress view, selector) without a terminal.
var stdoutIsTTY = func() bool { return isTerminal(os.Stdout) }

// noColorEnv reports whether NO_COLOR asks for no colour: present and
// non-empty, whatever its value (https://no-color.org).
func noColorEnv() bool { return os.Getenv("NO_COLOR") != "" }

// isTerminal reports whether f is a terminal, counting the Cygwin and MSYS2
// pseudo-terminals Windows users run under. Every terminal decision in the
// CLI goes through it, so the progress view, the report's width and the
// styled help never disagree about the same stream.
func isTerminal(f *os.File) bool {
	return isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
}

// cmdContext returns the command's context, or Background when the command
// is driven outside Execute (tests, embedding).
func cmdContext(cmd *cobra.Command) context.Context {
	if cmd != nil {
		if ctx := cmd.Context(); ctx != nil {
			return ctx
		}
	}
	return context.Background()
}
