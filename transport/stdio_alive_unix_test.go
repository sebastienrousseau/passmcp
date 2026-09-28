// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build !windows

package transport_test

import (
	"os"
	"syscall"
)

// alive reports whether a pid still exists.
//
// Signal 0 performs the permission and existence checks without delivering
// anything, which is the only way to ask this question on Unix. The tests
// that call it are the ones asserting passmcp does not leave processes
// behind, so "trust Wait" is not good enough: Wait returning is what we are
// checking, not what we are assuming.
func alive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}
