// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
)

// exitReapGrace is how long a failed write waits for the process to be
// reaped before concluding the failure was something other than an exit.
// Long enough for Wait to return on a process that has already died, short
// enough not to be felt.
const exitReapGrace = 2 * time.Second

// exitError explains a dead process, with what it said on the way out.
func (s *Stdio) exitError() error {
	<-s.done
	msg := strings.TrimSpace(s.stderrSettled())
	switch {
	case s.waitErr != nil && msg != "":
		// Both wrapped, so a caller can test for ErrProcessExited and still
		// reach the *exec.ExitError underneath for the exit status.
		return fmt.Errorf("%w: %w; stderr: %s", ErrProcessExited, s.waitErr, truncateForError(msg))
	case s.waitErr != nil:
		return fmt.Errorf("%w: %w", ErrProcessExited, s.waitErr)
	case msg != "":
		return fmt.Errorf("%w; stderr: %s", ErrProcessExited, truncateForError(msg))
	}
	return ErrProcessExited
}

// truncateForError keeps the END of the message, not the beginning.
//
// The ring buffer already keeps the last bytes for the reason that a server
// which logs steadily and then dies puts the explanation last. Truncating
// from the front would throw that away again and show an operator the
// startup chatter instead of "fatal: config missing".
func truncateForError(s string) string {
	const limit = 400
	r := []rune(s)
	if len(r) <= limit {
		return s
	}
	return "…" + string(r[len(r)-limit:])
}

// Custody is what shutting the server down took, and what survived it.
//
// Both halves are properties of the server rather than of passmcp, and
// neither is observable until the process has been reaped — which is why
// they are recorded here by Close rather than reported by a phase that
// runs while the server is still up.
type Custody struct {
	// Supported is false where the platform cannot track a process tree,
	// in which case Orphans means nothing and must not be read as "none".
	Supported bool
	// Forced is true when closing stdin did not end the server and it had
	// to be signalled.
	Forced bool
	// Signalled names the strongest signal it took, for the report.
	Signalled string
	// Orphans is true when processes were still in the server's group
	// after the server itself had exited.
	Orphans bool
	// AlreadyExited is true when the server was gone before shutdown
	// began, so "it stopped when its input closed" is not a thing that
	// happened and must not be reported as one.
	AlreadyExited bool
	// Err is anything that went wrong inspecting the group.
	Err error
}

// Custody reports what Close found. It is meaningful only after Close.
func (s *Stdio) Custody() Custody {
	if c, ok := s.custody.Load().(Custody); ok {
		return c
	}
	return Custody{Supported: processGroupsSupported}
}

// termGrace is how long a server gets between SIGTERM and SIGKILL.
//
// Short on purpose. It is the second grace period, not the first: this
// server has already been told to stop by the documented means, ignored it
// for the whole of ShutdownGrace, and then been signalled.
const termGrace = 2 * time.Second

// Close ends the server and waits for it.
//
// Politely first: closing stdin is how a well-behaved MCP server is told to
// stop, and most exit on their own. One that does not is signalled, its
// whole process group at once, and killed if it ignores that too. Close
// always returns having reaped the process — the one outcome this must
// never produce is a caller who thinks the server is gone while it is still
// running.
//
// On the way it records two things nothing else can see: whether the server
// needed to be forced, and whether anything it started outlived it.
func (s *Stdio) Close() error {
	if s.closed.Swap(true) {
		<-s.shut
		return nil
	}
	defer close(s.shut)

	c := Custody{Supported: processGroupsSupported}
	pid := s.PID()

	// Asked before stdin is closed, because afterwards the two cases look
	// identical and only one of them is the server behaving well.
	select {
	case <-s.done:
		c.AlreadyExited = true
	default:
	}
	_ = s.stdin.Close()

	select {
	case <-s.done:
		// Exited on its own, which is the correct behaviour. Look for
		// survivors before doing anything that would kill them, or the
		// cleanup would destroy the evidence it exists to find.
		c.Orphans, c.Err = s.survivors(pid)
	case <-time.After(s.cfg.ShutdownGrace):
		c.Forced = true
		c.Signalled = "SIGTERM"
		if err := s.terminateGroup(pid); err != nil {
			c.Err = err
		}
		select {
		case <-s.done:
		case <-time.After(termGrace):
			c.Signalled = "SIGKILL"
			s.killGroup(pid)
			<-s.done
		}
		// A forced server's group was just signalled, so asking what is
		// left in it answers a question about the signal rather than about
		// the server. Orphans stays false and Forced carries the finding.
	}

	// Whatever was found, nothing may be left running: passmcp is a
	// diagnostic and leaking a process tree onto the operator's machine
	// would be a worse defect than any it reports.
	if c.Orphans {
		s.killGroup(pid)
	}
	<-s.done

	// The tree is gone, so whatever held the stderr write end has let go
	// and the drain can finish.
	_ = s.stderrSettled()

	s.custody.Store(c)
	return nil
}

// stderrDrainGrace bounds the wait for the last of the server's output
// once its process tree has ended.
const stderrDrainGrace = 500 * time.Millisecond

// stderrSettled returns the server's output, having waited for the drain
// to finish.
//
// This exists because of what changed underneath it. While os/exec owned
// the stderr copy, Wait joined the copier and `done` closing meant the
// buffer was whole -- so the error path could read it with no
// synchronisation at all. Draining on passmcp's own goroutine removed that
// guarantee and left the assumption behind, which showed up as a dying
// server's explanation missing from the error naming its death, under
// -race and nowhere else.
//
// Bounded, and done once: a descriptor inherited by something passmcp could
// not reach must not hang a caller building an error message, and must
// not cost the bound again on every later call.
func (s *Stdio) stderrSettled() string {
	s.drainOnce.Do(func() {
		select {
		case <-s.stderrDone:
		case <-time.After(stderrDrainGrace):
		}
	})
	return s.stderr.String()
}

// survivors reports whether anything remained in the server's group once
// the server itself was gone.
func (s *Stdio) survivors(pid int) (bool, error) {
	if !processGroupsSupported {
		return false, nil
	}
	return groupAlive(pid)
}

// terminateGroup asks the whole tree to stop.
func (s *Stdio) terminateGroup(pid int) error {
	if processGroupsSupported {
		if err := signalGroup(pid, syscall.SIGTERM); err != nil {
			return err
		}
		return nil
	}
	if s.cmd.Process != nil {
		return s.cmd.Process.Signal(syscall.SIGTERM)
	}
	return nil
}

// killGroup ends the whole tree, falling back to the one process this
// platform can reach.
func (s *Stdio) killGroup(pid int) {
	if processGroupsSupported {
		if err := signalGroup(pid, syscall.SIGKILL); err == nil {
			return
		}
	}
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
}

// Signal sends sig to the server, for a caller testing how it handles one.
func (s *Stdio) Signal(sig os.Signal) error {
	if s.cmd.Process == nil {
		return ErrProcessExited
	}
	return s.cmd.Process.Signal(sig)
}
