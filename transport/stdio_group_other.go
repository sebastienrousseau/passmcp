// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build !unix && !windows

package transport

import (
	"errors"
	"os"
	"os/exec"
)

// Neither POSIX process groups nor Job Objects exist here.
//
// This file covers the platforms that are neither unix nor Windows: js and
// wasip1, where the library packages are still expected to compile even
// though a WebAssembly host cannot start a stdio server at all, and any
// other port Go adds. StartStdio fails on them at cmd.Start; everything
// below exists so the package builds and reports the tree as untracked,
// the same honest outcome as on Windows.

// processGroupsSupported records that this platform cannot track a tree.
const processGroupsSupported = false

// errNoProcessGroups is why the group operations do nothing here.
var errNoProcessGroups = errors.New("transport: this platform has no process groups")

// setProcessGroup has nothing to set on this platform.
func setProcessGroup(*exec.Cmd) {}

// groupAlive cannot see the tree on this platform.
func groupAlive(int) (bool, error) { return false, errNoProcessGroups }

// killName is what Custody.Signalled records when the server had to be
// killed.
const killName = "kill"

// terminateTree has no polite form on this platform.
func terminateTree(int) (string, error) { return "", nil }

// killTree ends the one process this platform lets passmcp reach.
func killTree(p *os.Process, _ int) {
	if p != nil {
		_ = p.Kill()
	}
}
