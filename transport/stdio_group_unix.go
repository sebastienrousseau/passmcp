// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build !windows

package transport

import (
	"errors"
	"os/exec"
	"syscall"
)

// Owning the process is not the same as owning what the process starts.
//
// A server spawned with no special treatment shares passmcp's process group,
// so killing it kills the one process whose pid passmcp happens to know. A
// server that forked a worker and exited leaves that worker running,
// attached to passmcp's own group, invisible to Process.Kill and still
// holding whatever the worker held — a port, a lock, a credential in its
// environment. The host that runs this server for real has the same
// problem and no way to see it.
//
// Putting the child in its own process group fixes both halves at once. It
// gives passmcp a handle on the whole tree rather than on one pid, and it
// makes "did anything outlive the server" a question with an answer:
// signal 0 to the group says whether anybody is still in it.
//
// It also detaches the child from passmcp's terminal, which is the behaviour
// we want anyway. Ctrl-C at an interactive run now reaches passmcp alone, and
// passmcp shuts the server down the documented way — by closing stdin —
// instead of the terminal delivering SIGINT to both and racing.

// processGroupsSupported records that this platform can do the above.
const processGroupsSupported = true

// setProcessGroup makes the child the leader of a new process group, so
// its pid is also its group id.
func setProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// signalGroup sends sig to every process in the group led by pid.
//
// A negative pid is the group form of kill(2). It is the whole point of
// the exercise: the server's own children receive it too, whether or not
// the server bothered to forward anything.
func signalGroup(pid int, sig syscall.Signal) error {
	if pid <= 0 {
		return errors.New("transport: no process group to signal")
	}
	return syscall.Kill(-pid, sig)
}

// groupAlive reports whether any process remains in the group led by pid.
//
// Signal 0 performs the permission and existence checks and delivers
// nothing, which is exactly the question being asked. ESRCH means the group
// is empty; EPERM means somebody is in it who is no longer ours, which is
// still somebody.
func groupAlive(pid int) (bool, error) {
	if pid <= 0 {
		return false, errors.New("transport: no process group to inspect")
	}
	err := syscall.Kill(-pid, 0)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, syscall.ESRCH):
		return false, nil
	case errors.Is(err, syscall.EPERM):
		return true, nil
	default:
		return false, err
	}
}
