// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build windows

package transport

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

// Windows has no process groups in the POSIX sense.
//
// CREATE_NEW_PROCESS_GROUP exists and is worth setting — it detaches the
// child from passmcp's console so a Ctrl-C at an interactive run does not go
// to both — but it gives no way to signal the tree. The mechanism that does
// is a Job Object: every process the server starts after it joins the job
// joins it too, and a job created with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
// takes all of them down when its last handle closes. That is what ends
// `cmd.exe /c npx …`, where the process passmcp knows is the shell and the
// one holding resources is the node.exe it started.
//
// The calls are made through the standard library's syscall package
// rather than golang.org/x/sys/windows, because the library packages
// import only the standard library. kernel32.dll is a KnownDLL, so loading
// it by name cannot be redirected by the search path.
//
// The job ends the tree; it does not yet answer whether anything outlived
// the server. A process can be assigned to a job only once it exists, so
// there is a window between cmd.Start and the assignment in which the
// server could start a child that never joins. Saying "nothing was left
// behind" would be a claim about that window too, so this platform still
// reports the question as unsupported and the check records a skip.

// processGroupsSupported records that this platform cannot answer
// whether anything outlived the server.
const processGroupsSupported = false

// errNoProcessGroups is why groupAlive does nothing here.
var errNoProcessGroups = errors.New(
	"transport: Windows has no POSIX process group; whether anything outlived the server is not tracked")

// setProcessGroup detaches the child from passmcp's console.
func setProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= syscall.CREATE_NEW_PROCESS_GROUP
}

// groupAlive cannot see the tree on this platform.
func groupAlive(int) (bool, error) { return false, errNoProcessGroups }

// terminateTree has no polite form on Windows.
//
// os.Process.Signal supports only Kill here and returns an error for
// SIGTERM, so sending one would record a signal that never left passmcp
// and then wait termGrace for an effect that cannot come. An empty name
// tells Close to go straight to the kill.
func terminateTree(int) (string, error) { return "", nil }

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	procTerminateJobObject       = kernel32.NewProc("TerminateJobObject")
)

const (
	// jobObjectExtendedLimitInformation is the information class
	// SetInformationJobObject takes JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	// under.
	jobObjectExtendedLimitInformation = 9
	// jobObjectLimitKillOnJobClose ends every process in the job when the
	// last handle to the job is closed.
	jobObjectLimitKillOnJobClose = 0x2000
	// processSetQuota and processTerminate are the access rights
	// AssignProcessToJobObject requires on the process handle.
	processSetQuota  = 0x0100
	processTerminate = 0x0001
	// limitFlagsOffset is where LimitFlags sits in
	// JOBOBJECT_BASIC_LIMIT_INFORMATION, after two LARGE_INTEGERs, on
	// every architecture.
	limitFlagsOffset = 16
)

// extendedLimitSize is sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION).
//
// The structure is built as bytes rather than declared as a Go struct
// because its layout differs by architecture in a way Go's alignment does
// not reproduce: on 386 the C compiler pads the basic limits to 48 bytes
// for their LARGE_INTEGER members and Go would not. Only LimitFlags is
// set, and its offset is the same everywhere.
func extendedLimitSize() int {
	ptr := int(unsafe.Sizeof(uintptr(0)))
	basic := 64 // two int64, five pointer-sized or DWORD fields, padded
	if ptr == 4 {
		basic = 48
	}
	const ioCounters = 6 * 8
	return basic + ioCounters + 4*ptr
}

// processTree is the Job Object that holds the server and what it starts.
// A zero job means none could be created, and only the server's own
// process can be killed.
type processTree struct {
	job syscall.Handle
}

// adopt puts the freshly started server into a new kill-on-close job.
//
// Failure is not fatal: the server runs as it did before Job Objects were
// used, and kill falls back to the one process passmcp holds.
func (t *processTree) adopt(p *os.Process) {
	if p == nil {
		return
	}
	job, err := newKillOnCloseJob()
	if err != nil {
		return
	}
	if assignToJob(job, p.Pid) != nil {
		_ = syscall.CloseHandle(job)
		return
	}
	t.job = job
}

// kill ends the whole job, or the one process when there is no job, and
// returns the name of the call that did it.
func (t *processTree) kill(p *os.Process, _ int) string {
	if t.job != 0 {
		if r, _, _ := procTerminateJobObject.Call(uintptr(t.job), 1); r != 0 {
			return "TerminateJobObject"
		}
	}
	if p != nil {
		_ = p.Kill()
	}
	return "TerminateProcess"
}

// release closes the job. Kill-on-close makes this the backstop: whatever
// is still in the job when Close finishes is ended here, including a
// child the server left behind when it exited on its own.
func (t *processTree) release() {
	if t.job != 0 {
		_ = syscall.CloseHandle(t.job)
		t.job = 0
	}
}

// newKillOnCloseJob creates an unnamed job whose processes die with its
// last handle.
func newKillOnCloseJob() (syscall.Handle, error) {
	r, _, err := procCreateJobObjectW.Call(0, 0)
	if r == 0 {
		return 0, err
	}
	job := syscall.Handle(r)
	info := make([]byte, extendedLimitSize())
	binary.LittleEndian.PutUint32(info[limitFlagsOffset:], jobObjectLimitKillOnJobClose)
	r, _, err = procSetInformationJobObject.Call(
		uintptr(job),
		jobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info[0])), //nolint:gosec // G103: the Win32 call takes a pointer; info is live for the call
		uintptr(len(info)),
	)
	if r == 0 {
		_ = syscall.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

// assignToJob places the process with this pid in the job.
//
// The pid cannot have been reused: os/exec holds a handle to the process
// until it is reaped, and Windows does not recycle a pid while a handle
// to it is open.
func assignToJob(job syscall.Handle, pid int) error {
	h, err := syscall.OpenProcess(processSetQuota|processTerminate, false, uint32(pid)) // #nosec G115 -- a Windows pid is a DWORD
	if err != nil {
		return err
	}
	defer func() { _ = syscall.CloseHandle(h) }()
	if r, _, err := procAssignProcessToJobObject.Call(uintptr(job), uintptr(h)); r == 0 {
		return err
	}
	return nil
}
