// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build windows

package transport_test

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"satellion.com/passmcp/transport"
)

// helperEnv selects what the re-executed test binary does instead of
// running the tests. The shell-script fixtures the other stdio tests use do
// not exist on Windows, so the fixture here is this binary itself.
const helperEnv = "PASSMCP_TRANSPORT_HELPER"

// pidFileEnv names the file a spawning helper writes its child's pid to.
const pidFileEnv = "PASSMCP_TRANSPORT_PIDFILE"

func TestMain(m *testing.M) {
	if mode := os.Getenv(helperEnv); mode != "" {
		os.Exit(runHelper(mode))
	}
	os.Exit(m.Run())
}

// runHelper is the fixture server.
//
//   - "ignore-eof" ignores its stdin and stays up, the misbehaviour Close
//     has to force.
//   - "spawn" starts an "ignore-eof" child of its own, the shape of
//     `cmd.exe /c npx …`, then ignores its stdin too.
//   - "spawn-exit" starts the same child and exits when its stdin closes,
//     leaving the child behind.
func runHelper(mode string) int {
	switch mode {
	case "ignore-eof":
		time.Sleep(time.Minute)
		return 0
	case "spawn":
		if spawnGrandchild() != nil {
			return 3
		}
		time.Sleep(time.Minute)
		return 0
	case "spawn-exit":
		if spawnGrandchild() != nil {
			return 3
		}
		_, _ = io.Copy(io.Discard, os.Stdin)
		return 0
	default:
		return 2
	}
}

// spawnGrandchild starts this binary again as an "ignore-eof" helper and
// records its pid where the test can find it.
func spawnGrandchild() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	//nolint:noctx // a fixture that must outlive this call
	cmd := exec.Command(exe, "-test.run=^$") // #nosec G204 -- the test binary itself
	cmd.Env = append(os.Environ(), helperEnv+"=ignore-eof")
	if err := cmd.Start(); err != nil {
		return err
	}
	return os.WriteFile(os.Getenv(pidFileEnv), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600)
}

// startHelper runs this test binary as a stdio server in the given mode.
func startHelper(t *testing.T, mode string, grace time.Duration, inject ...string) *transport.Stdio {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return start(t, transport.StdioConfig{
		Command:       exe,
		Args:          []string{"-test.run=^$"},
		Inject:        append([]string{helperEnv + "=" + mode}, inject...),
		ShutdownGrace: grace,
	})
}

// Windows has no SIGTERM. os.Process.Signal returns an error for it, so a
// Close that sent one anyway recorded a signal that never left passmcp,
// then waited the whole SIGTERM grace for nothing before killing. A forced
// Close goes straight to the kill and says so.
func TestStdioForcedCloseOnWindowsKillsWithoutSIGTERM(t *testing.T) {
	const grace = 300 * time.Millisecond
	s := startHelper(t, "ignore-eof", grace)

	began := time.Now()
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	took := time.Since(began)

	c := s.Custody()
	if !c.Forced {
		t.Fatal("a server that ignores EOF was not recorded as forced")
	}
	if c.Signalled != "TerminateJobObject" {
		t.Errorf("Signalled = %q, want TerminateJobObject; Windows sends no SIGTERM", c.Signalled)
	}
	if c.Err != nil {
		t.Errorf("Custody.Err = %v; nothing unsupported should have been attempted", c.Err)
	}
	// The SIGTERM grace is two seconds. Waiting it out would put Close
	// well past this bound.
	if limit := grace + time.Second; took > limit {
		t.Errorf("Close took %s, want under %s: it waited for a signal Windows cannot send", took, limit)
	}
	if exited, _ := s.Exited(); !exited {
		t.Error("Close returned while the process was still running")
	}
}

// Killing the process passmcp started is not killing what it started. A
// server launched through a shell is the shell; the process holding the
// port is its child. The Job Object takes the child down with it.
func TestStdioForcedCloseOnWindowsEndsTheGrandchild(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	s := startHelper(t, "spawn", 300*time.Millisecond, pidFileEnv+"="+pidFile)
	child := waitForPID(t, pidFile)

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if c := s.Custody(); c.Signalled != "TerminateJobObject" {
		t.Errorf("Signalled = %q, want TerminateJobObject", c.Signalled)
	}
	requireGone(t, child)
}

// A server that exits politely can still leave a child behind. Closing the
// job's last handle is the backstop that ends it.
func TestStdioCloseOnWindowsEndsWhatAPoliteServerLeft(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	s := startHelper(t, "spawn-exit", 5*time.Second, pidFileEnv+"="+pidFile)
	child := waitForPID(t, pidFile)

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if c := s.Custody(); c.Forced {
		t.Errorf("a server that exits on EOF was forced (%s)", c.Signalled)
	}
	requireGone(t, child)
}

// waitForPID reads the pid a spawning helper wrote, and arranges for that
// process to be killed if the test fails with it still running.
func waitForPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(path) // #nosec G304 -- the test's own temp file
		if pid, perr := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && perr == nil && pid > 0 {
			t.Cleanup(func() {
				if p, err := os.FindProcess(pid); err == nil {
					_ = p.Kill()
				}
			})
			return pid
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the helper never reported its child's pid")
	return 0
}

// requireGone fails unless the process with this pid has ended or ends
// within a few seconds.
func requireGone(t *testing.T, pid int) {
	t.Helper()
	h, err := syscall.OpenProcess(syscall.SYNCHRONIZE, false, uint32(pid)) // #nosec G115 -- a Windows pid is a DWORD
	if err != nil {
		return // no such process
	}
	defer func() { _ = syscall.CloseHandle(h) }()
	if ev, _ := syscall.WaitForSingleObject(h, 5000); ev != syscall.WAIT_OBJECT_0 {
		t.Errorf("process %d, started by the server, survived Close", pid)
	}
}
