// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// expect registers a waiter for id.
func (s *Stdio) expect(id int64) (chan reply, error) {
	ch := make(chan reply, 1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readErr != nil {
		return nil, s.readErr
	}
	s.waiters[id] = ch
	return ch, nil
}

// expectAny registers a waiter for the next unclaimed message.
func (s *Stdio) expectAny() (chan reply, error) {
	ch := make(chan reply, 1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readErr != nil {
		return nil, s.readErr
	}
	s.anyWaiters = append(s.anyWaiters, ch)
	return ch, nil
}

// forget removes a waiter, so an abandoned call does not leave the reader
// holding a channel nobody will read.
func (s *Stdio) forget(id int64, ch chan reply) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.waiters[id] == ch {
		delete(s.waiters, id)
	}
}

func (s *Stdio) forgetAny(ch chan reply) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, w := range s.anyWaiters {
		if w == ch {
			s.anyWaiters = append(s.anyWaiters[:i], s.anyWaiters[i+1:]...)
			return
		}
	}
}

// await blocks until the reply arrives, the caller gives up, or the server
// exits.
//
// Giving up does not end the process. That is a deliberate change from the
// first version of this file, which killed the server on a cancelled call
// because the read happened inline and there was no other way to free it.
// A per-call timeout is an ordinary finding about one slow method; making
// it fatal to the session meant a single slow tool ended the run, which
// the same timeout over HTTP never does. Custody still holds: the process
// belongs to Close, and every caller defers one.
func (s *Stdio) await(ctx context.Context, ch chan reply) (reply, error) {
	select {
	case r := <-ch:
		return r, r.err
	case <-ctx.Done():
		return reply{}, ctx.Err()
	case <-s.done:
		// Drain a reply that landed just before exit rather than reporting
		// a crash for a call that was in fact answered.
		select {
		case r := <-ch:
			return r, r.err
		case <-time.After(100 * time.Millisecond):
		}
		return reply{}, s.exitError()
	}
}

// read owns the pipe for the life of the connection.
func (s *Stdio) read() {
	for {
		line, err := s.readLine()
		if err != nil {
			s.failAll(err)
			return
		}
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var resp Response
		if err := json.Unmarshal(line, &resp); err != nil {
			// Not a framing error — the newline already says where the next
			// message starts — but a protocol violation, and one that
			// cannot be papered over: a caller waiting for a reply would
			// wait forever while this reader skipped garbage. Recording it
			// and ending the connection is what lets the probe report the
			// cause instead of a timeout.
			s.note(line)
			s.failAll(fmt.Errorf("transport: server wrote a line that is not JSON: %w", err))
			return
		}
		s.deliver(&resp, line)
	}
}

// note records a line that was not a JSON-RPC message.
func (s *Stdio) note(line []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.noise++
	if s.noiseSample == "" {
		s.noiseSample = strings.TrimSpace(string(line))
	}
}

// deliver hands a message to its waiter.
//
// A message matching an outstanding id goes to that call. Anything else —
// a notification, a request from the server, an error with a null id —
// goes to the oldest waiter that asked for whatever came next, and is
// counted as unsolicited when there is none. It is never mistaken for
// another call's answer, which is the one outcome that would corrupt a
// report.
func (s *Stdio) deliver(resp *Response, line []byte) {
	s.mu.Lock()
	var ch chan reply
	if resp.ID != nil {
		if w, ok := s.waiters[*resp.ID]; ok {
			ch = w
			delete(s.waiters, *resp.ID)
		}
	}
	if ch == nil && len(s.anyWaiters) > 0 {
		ch = s.anyWaiters[0]
		s.anyWaiters = s.anyWaiters[1:]
	}
	s.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- reply{resp: resp, line: line}:
	default:
	}
}

// failAll ends every outstanding call with err and refuses new ones.
func (s *Stdio) failAll(err error) {
	s.mu.Lock()
	if s.readErr == nil {
		s.readErr = err
	}
	ws := make([]chan reply, 0, len(s.waiters)+len(s.anyWaiters))
	for id, ch := range s.waiters {
		ws = append(ws, ch)
		delete(s.waiters, id)
	}
	ws = append(ws, s.anyWaiters...)
	s.anyWaiters = nil
	s.mu.Unlock()
	for _, ch := range ws {
		select {
		case ch <- reply{err: err}:
		default:
		}
	}
}

// readLine reads one newline-terminated message, bounded by MaxLine.
func (s *Stdio) readLine() ([]byte, error) {
	var buf []byte
	for {
		chunk, isPrefix, err := s.stdout.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, s.exitError()
			}
			return nil, err
		}
		buf = append(buf, chunk...)
		if len(buf) > s.cfg.MaxLine {
			// Ending the connection is the point. A peer sending an
			// unbounded line is broken or hostile, and continuing to read
			// is how a diagnostic becomes the outage.
			_ = s.Close()
			return nil, fmt.Errorf("%w: %d bytes without a newline", ErrLineTooLong, len(buf))
		}
		if !isPrefix {
			return buf, nil
		}
	}
}

// writeLine sends one message.
func (s *Stdio) writeLine(ctx context.Context, line []byte) error {
	if s.closed.Load() {
		return ErrProcessExited
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.stdin.Write(append(line, '\n')); err != nil {
		// A write to a server that has just died fails with EPIPE, and the
		// reaping goroutine may not have finished yet — so asking Exited
		// immediately can answer "still running" about a process that is
		// already gone, and the caller gets "broken pipe" instead of the
		// exit status and the stderr that explain it. Wait briefly for the
		// reap before deciding; a genuinely live server never gets here.
		select {
		case <-s.done:
			return s.exitError()
		case <-time.After(exitReapGrace):
		}
		return fmt.Errorf("transport: write to server: %w", err)
	}
	return nil
}
