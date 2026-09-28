// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build windows

package transport_test

// alive exists so the stdio tests compile on Windows. They skip there —
// their fixture servers are shell scripts — but a test file that does not
// build fails the platform outright, which is a worse outcome than a
// skipped test and is how this was first found.
//
// It reports false rather than guessing: nothing on Windows calls it, and a
// stub that pretended to check would be worse than one that says it does
// not.
func alive(int) bool { return false }
