// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build !windows

package transport_test

import (
	"context"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"satellion.com/passmcp/transport"
)

// politeGrace is how long these tests give a server that is supposed to
// exit on its own.
//
// Generous, and it costs nothing: Close returns the moment the process
// goes, so the only run that waits this long is one where the server did
// not stop — which is a different test. It is this large because three
// seconds was not always enough under `-race -shuffle` with the whole
// suite running, and a server that has not been scheduled yet is not a
// server that ignored its input.
const politeGrace = 20 * time.Second

// groupOf returns the process group id of pid, or 0.
func groupOf(t *testing.T, pid int) int {
	t.Helper()
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		return 0
	}
	return pgid
}

// TestStdioChildLeadsItsOwnProcessGroup is the precondition for everything
// else here: if the child shares passmcp's group, passmcp can neither signal
// the tree nor ask what is left in it.
func TestStdioChildLeadsItsOwnProcessGroup(t *testing.T) {
	s := start(t, transport.StdioConfig{Command: script(t, `
while read -r line; do :; done
`)})

	pid := s.PID()
	if pid <= 0 {
		t.Fatal("no pid")
	}
	if got := groupOf(t, pid); got != pid {
		t.Errorf("child is in group %d, want its own group %d", got, pid)
	}
	if got := groupOf(t, os.Getpid()); got == pid {
		t.Error("the child shares the test process's group")
	}
}

// TestStdioCleanExitIsNotForced: a server that stops when stdin closes is
// the correct behaviour, and Close must report that it did not have to do
// anything about it.
func TestStdioCleanExitIsNotForced(t *testing.T) {
	s, err := transport.StartStdio(context.Background(), transport.StdioConfig{
		Command:       script(t, "while read -r line; do :; done\nexit 0\n"),
		ShutdownGrace: politeGrace,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	c := s.Custody()
	if !c.Supported {
		t.Fatal("process groups should be supported on this platform")
	}
	if c.Forced {
		t.Errorf("a server that exited on stdin close was recorded as forced (%s)", c.Signalled)
	}
	if c.Orphans {
		t.Error("a server that started nothing was recorded as leaving orphans")
	}
	if c.Err != nil {
		t.Errorf("inspecting the group failed: %v", c.Err)
	}
}

// TestStdioForcesAServerThatIgnoresEverything is the fixture the roadmap
// names: it ignores the close of stdin and it ignores SIGTERM, so only the
// kill ends it. Close must still return having reaped it.
func TestStdioForcesAServerThatIgnoresEverything(t *testing.T) {
	s, err := transport.StartStdio(context.Background(), transport.StdioConfig{
		// It announces itself on stderr once the trap is installed. Without
		// that the test races the shell: a SIGTERM arriving before the trap
		// line has run kills the fixture by default, and the escalation
		// this test exists to check never happens. It showed up only under
		// the load of the full package run.
		Command: script(t, `
trap '' TERM
echo trap-installed >&2
while :; do sleep 0.05; done
`),
		ShutdownGrace: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	pid := s.PID()

	ready := time.Now().Add(10 * time.Second)
	for !strings.Contains(s.Stderr(), "trap-installed") {
		if time.Now().After(ready) {
			t.Fatal("the fixture never reported its trap installed")
		}
		time.Sleep(20 * time.Millisecond)
	}

	done := make(chan error, 1)
	go func() { done <- s.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Close never returned on a server that ignores every signal")
	}

	c := s.Custody()
	if !c.Forced {
		t.Error("a server that ignored stdin close was not recorded as forced")
	}
	if c.Signalled != "SIGKILL" {
		t.Errorf("a server that ignores SIGTERM should have needed SIGKILL, got %q", c.Signalled)
	}

	// The whole point: nothing is left running.
	//
	// Polled rather than asserted outright. SIGKILL is delivered
	// immediately but reaping is not: the shell's own children are
	// reparented and collected by init, and until that happens they are
	// zombies, which signal 0 still reports as present. Linux showed this
	// and macOS did not, because the timing differs. What is being
	// asserted is that the group empties, not that it has emptied by the
	// instant Close returned.
	deadline := time.Now().Add(5 * time.Second)
	for groupStillThere(pid) {
		if time.Now().After(deadline) {
			t.Error("the process group survived Close")
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestStdioSeesAnOrphanedChild is the other roadmap fixture: the server
// forks a worker and exits cleanly, which every existing check reads as a
// well-behaved shutdown. The worker is still holding whatever it held.
func TestStdioSeesAnOrphanedChild(t *testing.T) {
	s, err := transport.StartStdio(context.Background(), transport.StdioConfig{
		Command: script(t, `
sleep 30 &
while read -r line; do :; done
exit 0
`),
		ShutdownGrace: politeGrace,
	})
	if err != nil {
		t.Fatal(err)
	}
	pid := s.PID()

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	c := s.Custody()
	if c.Forced {
		// Not a failure of the thing under test: a forced shutdown kills
		// the group, so the orphan question is deliberately unanswerable
		// afterwards. Saying which happened keeps the next reader from
		// chasing the wrong bug.
		t.Fatalf("the server had to be signalled (%s), so this test could not observe an orphan; "+
			"it is supposed to exit on stdin close within %s", c.Signalled, politeGrace)
	}
	if !c.Orphans {
		t.Fatal("a worker that outlived the server was not seen")
	}

	// Seeing it is half the job. Leaking it onto the operator's machine
	// would be a worse defect than any passmcp reports, so Close also has to
	// have cleaned it up.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !groupStillThere(pid) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Error("the orphaned worker was reported but not reaped")
}

// TestStdioCustodyBeforeCloseIsNotAVerdict: reading custody early must not
// claim that nothing was left behind, because nothing has been looked at.
func TestStdioCustodyBeforeCloseIsNotAVerdict(t *testing.T) {
	s := start(t, transport.StdioConfig{Command: script(t, "while read -r line; do :; done\n")})

	c := s.Custody()
	if c.Forced || c.Orphans {
		t.Errorf("custody before Close reported an outcome: %+v", c)
	}
}

// TestStdioCloseRecordsCustodyOnce: the second caller waits for the first and
// reads the same answer rather than a zero one.
func TestStdioCloseRecordsCustodyOnce(t *testing.T) {
	s, err := transport.StartStdio(context.Background(), transport.StdioConfig{
		Command:       script(t, "sleep 30 &\nwhile read -r line; do :; done\nexit 0\n"),
		ShutdownGrace: politeGrace,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	first := s.Custody()
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if second := s.Custody(); second != first {
		t.Errorf("a second Close changed the record: %+v then %+v", first, second)
	}
}

// groupStillThere reports whether any process remains in pid's group. It
// mirrors the unexported helper so the test asserts on the real condition
// rather than on the implementation's own answer.
func groupStillThere(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(-pid, 0)
	return err == nil || err == syscall.EPERM
}

// TestStdioExitIsNotDelayedByAGrandchild is a regression test for a bug the
// custody work uncovered.
//
// os/exec copies a plain io.Writer stderr on a goroutine that Wait joins,
// so Wait returned when the last holder of the stderr descriptor let go
// rather than when the server exited. A server that starts a worker and
// exits leaves that worker holding it. Before the fix the shell here was
// gone within half a second and Exited() still reported false five seconds
// later, which every check that asks "is it still running" read as a
// server that was still up.
func TestStdioExitIsNotDelayedByAGrandchild(t *testing.T) {
	s, err := transport.StartStdio(context.Background(), transport.StdioConfig{
		// Exits as soon as stdin closes, leaving a worker holding the
		// descriptors it inherited.
		Command:       script(t, "sleep 5 &\nwhile read -r line; do :; done\nexit 0\n"),
		ShutdownGrace: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	pid := s.PID()
	t.Cleanup(func() { _ = s.Close() })

	go func() { _ = s.Close() }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if exited, _ := s.Exited(); exited {
			if groupStillThere(pid) {
				// Fine in principle, but the orphan must not still be
				// there once Close has finished with it.
				time.Sleep(200 * time.Millisecond)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Error("the server was reported as running for seconds after it exited, because a worker held its stderr")
}

// TestStdioKeepsStderrFromAServerThatDies is the property the previous
// design bought with that bug, and it has to survive the fix: a server
// that exits says why on stderr and nowhere else.
func TestStdioKeepsStderrFromAServerThatDies(t *testing.T) {
	s, err := transport.StartStdio(context.Background(), transport.StdioConfig{
		Command:       script(t, "echo 'missing GITHUB_TOKEN' >&2\nexit 3\n"),
		ShutdownGrace: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Let it die on its own first. Closing at once raced the shell: under
	// load, Close could end the process group before echo had run, and a
	// server killed before it wrote anything has nothing to keep — which is
	// correct, and not the property under test.
	deadline := time.Now().Add(5 * time.Second)
	for exited, _ := s.Exited(); !exited; exited, _ = s.Exited() {
		if time.Now().After(deadline) {
			t.Fatal("the server did not exit on its own")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := s.Stderr(); !strings.Contains(got, "missing GITHUB_TOKEN") {
		t.Errorf("the dying server's explanation was lost: %q", got)
	}
}
