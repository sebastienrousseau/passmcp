// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Most MCP servers in the wild are not endpoints. They are programs a host
// starts, talks to over a pipe, and is responsible for stopping — and that
// last part is the whole difference. An HTTP transport can walk away from a
// server that misbehaves. A stdio transport owns a process, and a tool that
// leaves one running has done harm no report can undo.
//
// Everything unusual in stdio*.go follows from custody: the lifecycle is
// explicit, every exit path goes through the same Close, stderr is kept
// because a server that dies says why there and nowhere else, and a line
// longer than the cap ends the connection rather than growing a buffer
// until the machine notices.

// Errors a stdio connection reports.
var (
	// ErrProcessExited means the server is gone. Whatever it was asked
	// cannot be answered, and retrying will not change that.
	ErrProcessExited = errors.New("transport: server process exited")
	// ErrLineTooLong means a single JSON-RPC message exceeded MaxLine. It
	// ends the connection: a peer that sends an unbounded line is either
	// broken or hostile, and the only safe reading of both is to stop.
	ErrLineTooLong = errors.New("transport: message exceeded the line limit")
)

// DefaultMaxLine bounds one JSON-RPC message. Large enough for a catalog of
// a thousand tools with full schemas; small enough that a server streaming
// an endless line is stopped in under a second rather than after the
// machine starts swapping.
const DefaultMaxLine = 16 << 20 // 16 MiB

// DefaultStderrCap bounds retained stderr. A server that writes a stack
// trace is why this exists; a server that writes a log line per request is
// why it is bounded.
const DefaultStderrCap = 64 << 10 // 64 KiB

// DefaultShutdownGrace is how long a server is given to exit after its
// stdin closes, before it is killed.
const DefaultShutdownGrace = 5 * time.Second

// StdioConfig describes a server to start.
type StdioConfig struct {
	// Command is the program, and Args its arguments. Command is used as
	// given: this is not a shell, so no expansion, quoting or globbing
	// happens, and a command containing a pipe is a command with a pipe in
	// its name.
	Command string
	Args    []string
	// Dir is the working directory; empty means the caller's.
	Dir string
	// Env replaces the environment entirely. A nil Env does NOT mean the
	// caller's environment: it means BaseEnv plus whatever PassEnv names.
	//
	// This is a deliberate departure from os/exec, where nil inherits
	// everything, and it is the whole point. passmcp starts a program the
	// operator named in order to find out what it does; handing it every
	// variable that happens to be exported — the cloud credentials, the
	// tokens for three other services, the CI secrets — is how a
	// credential reaches a program nobody audited. That is the same shape
	// as the exfiltration path this project already found once, and the
	// answer is the same: construct what is passed, do not sanitise what
	// was inherited.
	Env []string
	// PassEnv names variables to forward from the caller's environment.
	// A server that genuinely needs GITHUB_TOKEN is ordinary; forwarding
	// it by name is how the operator says so out loud.
	PassEnv []string
	// Inject are KEY=VALUE pairs added to the child's environment after
	// whatever Env or PassEnv produced, overriding a name set there.
	//
	// It exists for the variables passmcp sets about itself rather than on
	// the operator's behalf -- the proxy the egress witness runs, which
	// the server must dial through for anything to be observed. Keeping
	// them separate from Env means the rule that an environment is
	// constructed and never inherited still holds: this is passmcp adding
	// what it chose, not the caller's shell leaking in.
	Inject []string
	// MaxLine bounds one message; zero means DefaultMaxLine.
	MaxLine int
	// StderrCap bounds retained stderr; zero means DefaultStderrCap.
	StderrCap int
	// ShutdownGrace is how long the server has to exit after stdin closes;
	// zero means DefaultShutdownGrace.
	ShutdownGrace time.Duration
	// Observe, when set, is called after every exchange.
	//
	// It exists so a pipe can be recorded the way an HTTP exchange is. A
	// diagnostic whose findings cite "req#4" over HTTP and cite nothing
	// over stdio is a report that looks thinner for a reason that has
	// nothing to do with the server under test, and that is the kind of
	// difference an operator reads as a verdict.
	Observe func(ctx context.Context, m StdioMessage)
}

// StdioMessage is one exchange over the pipe.
type StdioMessage struct {
	// Sent is the line written, without its newline. Received is the line
	// read, or nil for a notification and for a call that failed.
	Sent     []byte
	Received []byte
	Duration time.Duration
	Err      error
}

// Stdio is a JSON-RPC connection to a server running as a child process,
// speaking newline-delimited JSON over stdin and stdout.
type Stdio struct {
	cfg StdioConfig

	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader

	protocolVersion atomic.Value // string
	sessionID       atomic.Value // string
	// custody is what Close found: whether the server had to be forced,
	// and whether anything it started outlived it. Written once by Close.
	custody atomic.Value // Custody
	nextID  atomic.Int64
	dialect atomic.Pointer[dialectBox]

	// writeMu serialises writes. Two goroutines interleaving halves of two
	// JSON lines produces a stream neither peer can parse, and the failure
	// looks like a protocol bug rather than a concurrency one.
	writeMu sync.Mutex

	// One goroutine reads the pipe and hands each message to whoever is
	// waiting for it. Callers never touch the reader.
	//
	// The obvious design is the other one: each call writes, then reads
	// until it sees its own id, under a mutex that keeps two calls from
	// reading each other's replies. It is simpler and it is wrong in three
	// ways that matter to a diagnostic. A call that times out leaves a
	// goroutine blocked on a pipe only the process can release, so the
	// only way out is to kill the server — which turns one slow tool into
	// a dead run, where the same timeout over HTTP is one finding.
	// Concurrent calls serialise, so the performance phase measures the
	// lock rather than the server. And a message with no id — the error a
	// server returns for a body it could not parse — can never be
	// matched, so the probe that sends malformed input cannot read the
	// answer.
	mu         sync.Mutex
	waiters    map[int64]chan reply
	anyWaiters []chan reply
	// readErr is set once the reader stops, so a later call fails with the
	// reason rather than waiting for a message that will never come.
	readErr error

	// shut closes when the first Close has finished recording custody, so
	// a second caller reads the same answer rather than racing the first
	// one to it.
	shut chan struct{}
	// stderrDone closes when the drain goroutine reaches EOF.
	stderrDone chan struct{}
	// drainOnce bounds the wait for it to at most one grace period.
	drainOnce sync.Once
	// noise counts lines the server wrote that were not JSON-RPC messages,
	// with the first kept as evidence. Writing anything else to stdout is
	// a protocol violation — the stream is the wire — and it is the single
	// most common way a stdio server is broken, because a stray print
	// statement is enough.
	noise       int
	noiseSample string

	stderr   *ringBuffer
	waitOnce sync.Once
	waitErr  error
	done     chan struct{}
	closed   atomic.Bool
}

// reply is one message the reader matched to a waiter, or the reason
// there will not be one.
type reply struct {
	resp *Response
	line []byte
	err  error
}

// StartStdio starts the server and returns a connection to it.
//
// The process is running when this returns. A caller that gets an error
// has no process to clean up; a caller that does not must Close.
func StartStdio(ctx context.Context, cfg StdioConfig) (*Stdio, error) {
	if strings.TrimSpace(cfg.Command) == "" {
		return nil, errors.New("transport: stdio needs a command")
	}
	cfg.applyDefaults()

	// Deliberately not exec.CommandContext, which noctx would prefer.
	//
	// CommandContext kills the child when ctx is cancelled. Two things make
	// that wrong here. The connection outlives this call by design, so the
	// context that started it is often a short-lived setup context whose
	// cancellation must not take the server with it. And on the paths where
	// a cancellation should end the process, Close already does it —
	// politely first, by closing stdin, then by force. Having os/exec kill
	// it as well means two owners of one lifetime and a race between them.
	//
	//nolint:noctx // lifetime is owned by Close; see above
	cmd := exec.Command(cfg.Command, cfg.Args...) // #nosec G204 -- the command is the operator's own argument; that is the feature
	cmd.Dir = cfg.Dir
	cmd.Env = cfg.environment()

	// Give the child its own process group, so passmcp owns the tree rather
	// than the one pid it was handed. See stdio_group_unix.go.
	setProcessGroup(cmd)

	p, err := openStdioPipes()
	if err != nil {
		return nil, err
	}
	cmd.Stdin = p.stdinRead
	cmd.Stdout = p.stdoutWrite

	s := &Stdio{
		cfg:        cfg,
		cmd:        cmd,
		stdin:      p.stdinWrite,
		stdout:     bufio.NewReaderSize(p.stdoutRead, 64<<10),
		stderr:     newRingBuffer(cfg.StderrCap),
		done:       make(chan struct{}),
		shut:       make(chan struct{}),
		stderrDone: make(chan struct{}),
		waiters:    map[int64]chan reply{},
	}
	cmd.Stderr = p.stderrWrite
	s.protocolVersion.Store("")
	s.sessionID.Store("")
	s.dialect.Store(&dialectBox{d: &Sessioned{}})

	if err := cmd.Start(); err != nil {
		p.closeAll()
		return nil, fmt.Errorf("transport: start %s: %w", cfg.Command, err)
	}

	// The child has its own descriptors now. Closing the parent's copies is
	// what makes EOF mean "the child exited" rather than "nobody is writing
	// yet", and what lets the child see EOF on stdin when Close shuts its
	// end.
	_ = p.stdinRead.Close()
	_ = p.stdoutWrite.Close()
	_ = p.stderrWrite.Close()

	// One goroutine drains stderr into the ring buffer. It ends when the
	// last holder of the write end lets go, which may be later than the
	// server's own exit; nothing waits on it except Close, and only
	// briefly.
	go func() {
		_, _ = io.Copy(s.stderr, p.stderrRead)
		_ = p.stderrRead.Close()
		close(s.stderrDone)
	}()

	// One goroutine owns Wait, so the exit status is available to every
	// caller and reaped exactly once.
	go func() {
		s.waitOnce.Do(func() { s.waitErr = cmd.Wait() })
		close(s.done)
	}()

	// One goroutine owns the pipe.
	go s.read()

	// A context already cancelled at Start means the caller has given up,
	// and leaving the process behind would be the one outcome this file
	// exists to prevent.
	if ctx != nil {
		select {
		case <-ctx.Done():
			_ = s.Close()
			return nil, ctx.Err()
		default:
		}
	}
	return s, nil
}

// applyDefaults fills every limit the caller left at zero.
func (cfg *StdioConfig) applyDefaults() {
	if cfg.MaxLine <= 0 {
		cfg.MaxLine = DefaultMaxLine
	}
	if cfg.StderrCap <= 0 {
		cfg.StderrCap = DefaultStderrCap
	}
	if cfg.ShutdownGrace <= 0 {
		cfg.ShutdownGrace = DefaultShutdownGrace
	}
}

// Dialect returns the binding in use.
func (s *Stdio) Dialect() Dialect { return s.dialect.Load().d }

// SetDialect replaces the binding.
func (s *Stdio) SetDialect(d Dialect) {
	if d == nil {
		return
	}
	s.dialect.Store(&dialectBox{d: d})
	if !d.Stateful() {
		s.sessionID.Store("")
	}
}

// SessionID returns the session identifier, which stdio never has: the
// connection is the session. It exists so a caller can treat the two
// transports alike.
func (s *Stdio) SessionID() string { return s.sessionID.Load().(string) }

// SetSessionID records a session identifier. It affects nothing on a pipe
// and is kept only so a stateful dialect behaves identically on both
// transports.
func (s *Stdio) SetSessionID(id string) { s.sessionID.Store(id) }

// ProtocolVersion returns the negotiated version.
func (s *Stdio) ProtocolVersion() string { return s.protocolVersion.Load().(string) }

// SetProtocolVersion records the negotiated version.
func (s *Stdio) SetProtocolVersion(v string) { s.protocolVersion.Store(v) }

// Reset drops per-session state.
//
// On HTTP this abandons a session and the next call starts a new one. A
// process has no equivalent — the session is the pipe — so this clears what
// it can and does not pretend to have restarted anything. A caller that
// wants a fresh server closes this one and starts another.
func (s *Stdio) Reset() {
	s.sessionID.Store("")
	s.protocolVersion.Store("")
}

// Stderr returns what the server has written to stderr, capped.
//
// This is not decoration. A stdio server that fails to start, crashes, or
// refuses its arguments says so on stderr and nowhere else; without this
// the diagnostic is "the process exited", which tells an operator nothing
// they can act on.
func (s *Stdio) Stderr() string {
	// Once the process has gone, the last of what it said may still be in
	// flight, and "it exited and said nothing" is the least useful thing
	// this can report. While it is running there is nothing to wait for.
	select {
	case <-s.done:
		return s.stderrSettled()
	default:
		return s.stderr.String()
	}
}

// Exited reports whether the process has finished, and its error if so.
func (s *Stdio) Exited() (bool, error) {
	select {
	case <-s.done:
		return true, s.waitErr
	default:
		return false, nil
	}
}

// PID returns the server's process id, or 0 before it starts. It exists so
// a caller — or a test — can verify the process is gone rather than trust
// that it is.
func (s *Stdio) PID() int {
	if s.cmd.Process == nil {
		return 0
	}
	return s.cmd.Process.Pid
}

// NextID returns the next request id, for a caller building a raw message.
func (s *Stdio) NextID() int64 { return s.nextID.Add(1) }

// Call sends a request and waits for the matching response.
func (s *Stdio) Call(ctx context.Context, method string, params any, result any) error {
	id := s.nextID.Add(1)
	req, err := buildRPC(&id, method, params)
	if err != nil {
		return err
	}
	if err := s.Dialect().PrepareBody(req); err != nil {
		return err
	}
	line, err := json.Marshal(req)
	if err != nil {
		return err
	}

	// The waiter is registered before the write, not after. A server can
	// answer faster than this goroutine is rescheduled, and a reply that
	// arrives before anybody is listening for it would be counted as
	// unsolicited and dropped.
	ch, err := s.expect(id)
	if err != nil {
		return err
	}
	defer s.forget(id, ch)

	start := time.Now()
	if err := s.writeLine(ctx, line); err != nil {
		s.observe(ctx, line, nil, time.Since(start), err)
		return err
	}
	r, err := s.await(ctx, ch)
	if err != nil {
		s.observe(ctx, line, nil, time.Since(start), err)
		return err
	}
	s.observe(ctx, line, r.line, time.Since(start), nil)
	resp := r.resp
	if resp == nil {
		return fmt.Errorf("%w: %s (id %d)", ErrNoResponse, method, id)
	}
	if resp.Error != nil {
		return AsProtocolError(s.Dialect().Version(), resp.Error)
	}
	if ir, ok := AsInputRequired(method, resp.Result); ok {
		return ir
	}
	if result != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, result); err != nil {
			return fmt.Errorf("transport: decode %s result: %w", method, err)
		}
	}
	return nil
}

// Notify sends a notification, which expects no response.
func (s *Stdio) Notify(ctx context.Context, method string, params any) error {
	req, err := buildRPC(nil, method, params)
	if err != nil {
		return err
	}
	if err := s.Dialect().PrepareBody(req); err != nil {
		return err
	}
	line, err := json.Marshal(req)
	if err != nil {
		return err
	}
	start := time.Now()
	err = s.writeLine(ctx, line)
	s.observe(ctx, line, nil, time.Since(start), err)
	return err
}
