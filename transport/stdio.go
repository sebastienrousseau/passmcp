// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Most MCP servers in the wild are not endpoints. They are programs a host
// starts, talks to over a pipe, and is responsible for stopping — and that
// last part is the whole difference. An HTTP transport can walk away from a
// server that misbehaves. A stdio transport owns a process, and a tool that
// leaves one running has done harm no report can undo.
//
// Everything unusual in this file follows from custody: the lifecycle is
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

// BaseEnv is what a server gets when the caller names nothing.
//
// A program needs to be able to find its interpreter and its libraries, and
// an empty environment breaks almost everything for no security gain — PATH
// is not a secret. Everything that might be one is left out.
var BaseEnv = []string{"PATH", "HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "SystemRoot", "COMSPEC", "PATHEXT"}

// environment builds what the child will see.
func (c StdioConfig) environment() []string {
	if c.Env != nil {
		// An explicit Env is exactly what the caller asked for, including
		// an explicitly empty one -- plus whatever passmcp injects about
		// itself, which the caller is not choosing between.
		return inject(append([]string{}, c.Env...), c.Inject)
	}
	names := append(append([]string{}, BaseEnv...), c.PassEnv...)
	seen := map[string]bool{}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		if v, ok := os.LookupEnv(n); ok {
			out = append(out, n+"="+v)
		}
	}
	// A non-nil empty slice, so os/exec does not fall back to inheriting
	// the caller's environment when nothing matched.
	return inject(out, c.Inject)
}

// inject appends passmcp's own variables, replacing any of the same name.
//
// Last-wins would be enough for os/exec, which takes the final assignment,
// but a duplicated name in a list somebody may read in a report is a
// second thing to explain.
func inject(env, extra []string) []string {
	if len(extra) == 0 {
		return env
	}
	names := make(map[string]bool, len(extra))
	for _, kv := range extra {
		if k, _, ok := strings.Cut(kv, "="); ok {
			names[k] = true
		}
	}
	out := make([]string, 0, len(env)+len(extra))
	for _, kv := range env {
		if k, _, ok := strings.Cut(kv, "="); ok && names[k] {
			continue
		}
		out = append(out, kv)
	}
	return append(out, extra...)
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

// StdioExchange describes one raw message to send, for a conformance probe
// that needs to send something the normal path would never produce.
type StdioExchange struct {
	// Body is sent verbatim, newline appended. It does not have to be
	// JSON: that is the point of the malformed-input probes.
	Body []byte
	// Request, when Body is nil, is marshalled instead.
	Request *Request
	// SkipDialect sends Request exactly as given, without the protocol
	// metadata the active dialect would otherwise add.
	SkipDialect bool
	// AnyMessage waits for the next message the server writes rather than
	// one matching an id.
	//
	// It is how the malformed-input probes read their answer: JSON-RPC
	// says a parse error is reported with a null id, so there is nothing
	// to match on. The cost is that a notification the server happened to
	// emit at that moment is taken for the answer — unavoidable with this
	// framing, and the reason this is opt-in rather than a fallback.
	AnyMessage bool
}

// StdioResult is what one raw exchange produced.
//
// There is no status code and no header: a pipe has neither, which is why
// this is a separate type from the HTTP transport's RawResult rather than
// that one with two fields left at zero for a caller to misread.
type StdioResult struct {
	// Line is the message the server wrote, verbatim.
	Line []byte
	// Response is set when Line parsed as a JSON-RPC response.
	Response *Response
	Duration time.Duration
}

// exchangeBody is the line Exchange writes: the caller's bytes as given, or
// the request marshalled, prepared for the dialect unless the probe skips it.
func (s *Stdio) exchangeBody(opts StdioExchange) ([]byte, error) {
	if opts.Body != nil {
		return opts.Body, nil
	}
	if opts.Request == nil {
		return nil, errors.New("transport: exchange needs a Body or a Request")
	}
	if !opts.SkipDialect {
		if err := s.Dialect().PrepareBody(opts.Request); err != nil {
			return nil, err
		}
	}
	return json.Marshal(opts.Request)
}

// Exchange sends one raw message and returns what the server answered.
//
// It is the pipe's counterpart to Streamable.Do, and it exists for the same
// reason: a conformance probe has to be able to send what a client library
// would refuse to. Unlike Do it cannot lie about transport framing, so the
// probes that are about HTTP — a missing Accept header, a session id the
// server never issued — have no form here and are reported as skipped
// rather than approximated.
func (s *Stdio) Exchange(ctx context.Context, opts StdioExchange) (*StdioResult, error) {
	body, err := s.exchangeBody(opts)
	if err != nil {
		return nil, err
	}
	// A newline inside the body would frame two messages, and the probe
	// would be measuring something other than what it wrote.
	if bytes.ContainsAny(body, "\n\r") {
		return nil, errors.New("transport: a raw stdio message cannot contain a newline")
	}

	var ch chan reply
	switch {
	case opts.AnyMessage || opts.Request == nil || opts.Request.ID == nil:
		ch, err = s.expectAny()
		defer s.forgetAny(ch)
	default:
		ch, err = s.expect(*opts.Request.ID)
		defer s.forget(*opts.Request.ID, ch)
	}
	if err != nil {
		return nil, err
	}

	start := time.Now()
	if err := s.writeLine(ctx, body); err != nil {
		s.observe(ctx, body, nil, time.Since(start), err)
		return nil, err
	}
	r, err := s.await(ctx, ch)
	if err != nil {
		s.observe(ctx, body, nil, time.Since(start), err)
		return nil, err
	}
	s.observe(ctx, body, r.line, time.Since(start), nil)
	return &StdioResult{Line: r.line, Response: r.resp, Duration: time.Since(start)}, nil
}

// Noise reports how many lines the server wrote to stdout that were not
// JSON-RPC messages, and the first of them.
//
// The stream is the wire: the specification says a stdio server must write
// nothing else there. A stray print statement is the most common way a
// stdio server is broken, and the symptom — a client that hangs or reports
// a parse error — never names the cause.
func (s *Stdio) Noise() (int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.noise, s.noiseSample
}

// observe reports one exchange, if anybody asked.
func (s *Stdio) observe(ctx context.Context, sent, recv []byte, d time.Duration, err error) {
	if s.cfg.Observe == nil {
		return
	}
	s.cfg.Observe(ctx, StdioMessage{Sent: sent, Received: recv, Duration: d, Err: err})
}

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

// buildRPC assembles a request. Shared with the HTTP transport's own
// builder in everything but the receiver.
func buildRPC(id *int64, method string, params any) (*Request, error) {
	r := &Request{JSONRPC: "2.0", ID: id, Method: method}
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("transport: encode params: %w", err)
		}
		r.Params = b
	}
	return r, nil
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
