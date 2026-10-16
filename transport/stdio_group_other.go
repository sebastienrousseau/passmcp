// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build !unix && !windows

package transport

import (
	"errors"
	"os/exec"
	"syscall"
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

// signalGroup cannot reach the tree on this platform.
func signalGroup(int, syscall.Signal) error { return errNoProcessGroups }

// groupAlive cannot see the tree on this platform.
func groupAlive(int) (bool, error) { return false, errNoProcessGroups }
