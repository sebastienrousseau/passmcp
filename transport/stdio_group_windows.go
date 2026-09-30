// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build windows

package transport

import (
	"errors"
	"os/exec"
	"syscall"
)

// Windows has no process groups in the POSIX sense.
//
// CREATE_NEW_PROCESS_GROUP exists and is worth setting — it detaches the
// child from passmcp's console so a Ctrl-C at an interactive run does not go
// to both — but it gives no way to signal the tree and no way to ask
// whether anything is left in it. The mechanism that does is a Job Object,
// and reaching it means golang.org/x/sys/windows. The module requires it
// (internal/creds reads the token store's access-control list with it),
// but this is a library package, and the library packages import only
// the standard library; that is not worth giving up for a single
// platform's single check.
//
// So this platform sets what it can, kills the process it knows about, and
// reports the rest as unsupported. The check that reads this records a
// skip naming the reason, which is the honest outcome: passmcp does not claim
// on Windows that nothing was left behind, because it cannot see.

// processGroupsSupported records that this platform cannot do the above.
const processGroupsSupported = false

// errNoProcessGroups is why the group operations do nothing here.
var errNoProcessGroups = errors.New(
	"transport: Windows has no POSIX process group; tracking the tree needs a Job Object")

// setProcessGroup detaches the child from passmcp's console.
func setProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= syscall.CREATE_NEW_PROCESS_GROUP
}

// signalGroup cannot reach the tree on this platform.
func signalGroup(int, syscall.Signal) error { return errNoProcessGroups }

// groupAlive cannot see the tree on this platform.
func groupAlive(int) (bool, error) { return false, errNoProcessGroups }
