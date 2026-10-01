// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import (
	"fmt"
	"os"
	"sync"
)

// stdioPipes are the parent's ends and the child's ends of the three pipes
// a stdio server is started with.
type stdioPipes struct {
	stdinRead, stdinWrite   *os.File
	stdoutRead, stdoutWrite *os.File
	stderrRead, stderrWrite *os.File
}

// openStdioPipes opens the three pipes, closing any already open if a
// later one fails.
func openStdioPipes() (*stdioPipes, error) {
	// os.Pipe rather than cmd.StdinPipe/StdoutPipe, and a plain writer for
	// stderr, because Wait closes the pipes those return. The documentation
	// says so plainly — "it is incorrect to call Wait before all reads from
	// the pipe have completed" — and this type has a goroutine that owns
	// Wait and a reader that lives for the whole connection, so the two
	// race by construction. CI caught it as an error that said the server
	// had exited without the stderr line explaining why: Wait had closed
	// the pipe before the drain read a byte.
	//
	// With os.Pipe the parent owns both ends and closes its own copies
	// after Start; the child keeps its own, so the reader sees a clean EOF
	// when the child exits and nothing else can close it underneath.
	var p stdioPipes
	var err error
	p.stdinRead, p.stdinWrite, err = os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("transport: stdin pipe: %w", err)
	}
	p.stdoutRead, p.stdoutWrite, err = os.Pipe()
	if err != nil {
		_ = p.stdinRead.Close()
		_ = p.stdinWrite.Close()
		return nil, fmt.Errorf("transport: stdout pipe: %w", err)
	}
	// stderr gets a pipe of its own for the same reason stdout does, and
	// for one more that only shows up on a server that forks.
	//
	// Handing os/exec a plain io.Writer makes it copy on a goroutine that
	// Wait joins — so Wait returns when the stderr descriptor is closed by
	// everybody holding it, not when the process exits. A server that
	// starts a worker and exits leaves that worker holding the descriptor,
	// and Wait then blocks for as long as the worker lives. Measured
	// before this was changed: the shell was gone at 0.5s and Exited()
	// still said false at 5.0s, released only when its `sleep 5` ended.
	// Every check that asks whether the server is still running read that,
	// and ShutdownGrace was being measured against a process that had
	// already exited.
	p.stderrRead, p.stderrWrite, err = os.Pipe()
	if err != nil {
		_ = p.stdinRead.Close()
		_ = p.stdinWrite.Close()
		_ = p.stdoutRead.Close()
		_ = p.stdoutWrite.Close()
		return nil, fmt.Errorf("transport: stderr pipe: %w", err)
	}
	return &p, nil
}

// closeAll closes every end of every pipe, for a server that never started.
func (p *stdioPipes) closeAll() {
	_ = p.stdinRead.Close()
	_ = p.stdinWrite.Close()
	_ = p.stdoutRead.Close()
	_ = p.stdoutWrite.Close()
	_ = p.stderrRead.Close()
	_ = p.stderrWrite.Close()
}

// ringBuffer keeps the last n bytes written to it.
//
// Last rather than first: a server that logs steadily and then dies pushes
// the interesting part to the end, and keeping the first 64 KiB of a chatty
// server's startup chatter would discard exactly the lines that explain the
// exit.
type ringBuffer struct {
	mu   sync.Mutex
	buf  []byte
	n    int
	full bool
}

func newRingBuffer(n int) *ringBuffer { return &ringBuffer{buf: make([]byte, n)} }

func (r *ringBuffer) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	total := len(p)
	if len(p) >= len(r.buf) {
		copy(r.buf, p[len(p)-len(r.buf):])
		r.n = 0
		r.full = true
		return total, nil
	}
	for _, b := range p {
		r.buf[r.n] = b
		r.n++
		if r.n == len(r.buf) {
			r.n = 0
			r.full = true
		}
	}
	return total, nil
}

func (r *ringBuffer) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.full {
		return string(r.buf[:r.n])
	}
	return string(r.buf[r.n:]) + string(r.buf[:r.n])
}
