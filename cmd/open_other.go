// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build !darwin && !windows

package cmd

// browserCommand is the program that opens a URL in the default browser:
// the freedesktop.org opener everywhere but macOS and Windows.
func browserCommand() (string, []string) { return "xdg-open", nil }
