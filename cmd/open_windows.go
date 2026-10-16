// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

// browserCommand is the program that opens a URL in the default browser.
func browserCommand() (string, []string) {
	return "rundll32", []string{"url.dll,FileProtocolHandler"}
}
