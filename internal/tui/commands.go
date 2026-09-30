// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package tui

import "strings"

// slashCommands are the in-session commands the filter line accepts.
var slashCommands = []string{"/exit", "/quit", "/help", "/all", "/none", "/sort"}

func completeSlashCommand(filter string) (string, bool) {
	if !strings.HasPrefix(filter, "/") {
		return "", false
	}
	for _, cmd := range slashCommands {
		if len(cmd) > len(filter) && strings.HasPrefix(cmd, filter) {
			return cmd, true
		}
	}
	return "", false
}
