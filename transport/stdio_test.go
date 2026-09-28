// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp/transport"
)

// The fixture servers are shell scripts rather than Go test binaries so a
// test can describe a misbehaviour in three lines. Windows has no sh, so
// every test here skips there; the transport itself is portable and the
// coverage gap is in the fixtures, not the code.
func requireShell(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fixture servers are shell scripts")
	}
}

// script writes an executable shell script and returns its path.
func script(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "server.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o700); err != nil { //nolint:gosec // a test fixture that has to be executable
		t.Fatal(err)
	}
	return p
}

// echoServer answers every request with a result echoing the method.
const echoServer = `
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  m=$(printf '%s' "$line" | sed -n 's/.*"method":"\([^"]*\)".*/\1/p')
  if [ -n "$id" ]; then
    printf '{"jsonrpc":"2.0","id":%s,"result":{"method":"%s"}}\n' "$id" "$m"
  fi
done
`

func start(t *testing.T, cfg transport.StdioConfig) *transport.Stdio {
	t.Helper()
	s, err := transport.StartStdio(context.Background(), cfg)
	if err != nil {
		t.Fatalf("StartStdio: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestStdioCallAndNotify(t *testing.T) {
	requireShell(t)
	s := start(t, transport.StdioConfig{Command: script(t, echoServer)})

	var got struct {
		Method string `json:"method"`
	}
	if err := s.Call(context.Background(), "tools/list", nil, &got); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if got.Method != "tools/list" {
		t.Errorf("result = %+v", got)
	}

	// A notification carries no id and must not wait for an answer.
	done := make(chan error, 1)
	go func() { done <- s.Notify(context.Background(), "notifications/initialized", nil) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Notify: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Notify waited for a response")
	}
}

// TestStdioMatchesResponsesByID: a server that interleaves notifications
// with responses must not have the notification mistaken for the answer.
func TestStdioMatchesResponsesByID(t *testing.T) {
	requireShell(t)
	s := start(t, transport.StdioConfig{Command: script(t, `
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  printf '{"jsonrpc":"2.0","method":"notifications/progress","params":{}}\n'
  printf '{"jsonrpc":"2.0","id":9999,"result":{"wrong":true}}\n'
  printf '{"jsonrpc":"2.0","id":%s,"result":{"right":true}}\n' "$id"
done
`)})

	var got struct {
		Right bool `json:"right"`
		Wrong bool `json:"wrong"`
	}
	if err := s.Call(context.Background(), "tools/list", nil, &got); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !got.Right || got.Wrong {
		t.Errorf("matched the wrong message: %+v", got)
	}
}

// TestStdioReportsAnRPCError checks the error path maps to the same typed
// error the HTTP transport produces.
func TestStdioReportsAnRPCError(t *testing.T) {
	requireShell(t)
	s := start(t, transport.StdioConfig{Command: script(t, `
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"no such method"}}\n' "$id"
done
`)})
	err := s.Call(context.Background(), "nope", nil, nil)
	if err == nil {
		t.Fatal("an error response was reported as success")
	}
	if !strings.Contains(err.Error(), "no such method") {
		t.Errorf("error does not carry the server's message: %v", err)
	}
}

// TestStdioServerThatExitsMidCall is the failure an HTTP transport never
// has: the peer is a process, and it can simply die.
func TestStdioServerThatExitsMidCall(t *testing.T) {
	requireShell(t)
	s := start(t, transport.StdioConfig{Command: script(t, `
echo "fatal: config missing" >&2
exit 3
`)})
	err := s.Call(context.Background(), "tools/list", nil, nil)
	if err == nil {
		t.Fatal("a call to a dead server succeeded")
	}
	if !errors.Is(err, transport.ErrProcessExited) {
		t.Errorf("error is not ErrProcessExited: %v", err)
	}
	// The reason the server died is on stderr and nowhere else. An error
	// that omits it leaves an operator with nothing to act on.
	if !strings.Contains(err.Error(), "config missing") {
		t.Errorf("error does not carry stderr: %v", err)
	}
}

func TestStdioStderrIsKept(t *testing.T) {
	requireShell(t)
	s := start(t, transport.StdioConfig{Command: script(t, `
echo "listening on stdio" >&2
`+echoServer)})
	if err := s.Call(context.Background(), "ping", nil, nil); err != nil {
		t.Fatalf("Call: %v", err)
	}
	// Give the drain goroutine a moment; stderr is asynchronous by nature.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(s.Stderr(), "listening") {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(s.Stderr(), "listening on stdio") {
		t.Errorf("stderr not captured: %q", s.Stderr())
	}
}

// TestStdioGarbageOutput: a server that writes something that is not JSON
// must produce an error naming that, not a nil dereference or a hang.
func TestStdioGarbageOutput(t *testing.T) {
	requireShell(t)
	s := start(t, transport.StdioConfig{Command: script(t, `
while IFS= read -r line; do
  echo "this is not json"
done
`)})
	err := s.Call(context.Background(), "tools/list", nil, nil)
	if err == nil {
		t.Fatal("garbage was accepted")
	}
	if !strings.Contains(err.Error(), "not JSON") {
		t.Errorf("error does not say what was wrong: %v", err)
	}
}

// TestStdioLineTooLong bounds a hostile server. Without the cap this test
// allocates until the machine gives up.
func TestStdioLineTooLong(t *testing.T) {
	requireShell(t)
	s := start(t, transport.StdioConfig{
		Command: script(t, `
read -r line
while :; do printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; done
`),
		MaxLine: 64 << 10,
	})
	err := s.Call(context.Background(), "tools/list", nil, nil)
	if err == nil {
		t.Fatal("an unbounded line was accepted")
	}
	if !errors.Is(err, transport.ErrLineTooLong) && !errors.Is(err, transport.ErrProcessExited) {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestStdioCloseEndsAPolitelyStoppingServer: closing stdin is how a
// well-behaved server is told to stop.
func TestStdioCloseEndsAPolitelyStoppingServer(t *testing.T) {
	requireShell(t)
	s := start(t, transport.StdioConfig{Command: script(t, echoServer)})
	if err := s.Call(context.Background(), "ping", nil, nil); err != nil {
		t.Fatalf("Call: %v", err)
	}
	start := time.Now()
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Close took %s; the server exits on EOF and should not have needed the grace period", d)
	}
	if exited, _ := s.Exited(); !exited {
		t.Error("Close returned with the process still running")
	}
}

// TestStdioCloseKillsAServerThatIgnoresEOF is the one that matters.
//
// A tool that leaves a process running has done harm no report can undo,
// and a server that ignores a closed stdin is not hypothetical — it is
// every server that reads with a timeout and loops.
func TestStdioCloseKillsAServerThatIgnoresEOF(t *testing.T) {
	requireShell(t)
	s := start(t, transport.StdioConfig{
		Command:       script(t, `trap '' TERM PIPE; while :; do sleep 0.05; done`),
		ShutdownGrace: 300 * time.Millisecond,
	})
	pid := s.PID()
	if pid <= 0 {
		t.Fatalf("no pid: %d", pid)
	}

	done := make(chan struct{})
	go func() { _ = s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Close never returned on a server that ignores EOF")
	}

	if exited, _ := s.Exited(); !exited {
		t.Fatal("Close returned while the process was still running")
	}
	if alive(pid) {
		t.Errorf("process %d survived Close", pid)
	}
}

// TestStdioCloseIsIdempotent: Close runs on a defer and on an error path,
// and a second call must not block or panic.
func TestStdioCloseIsIdempotent(t *testing.T) {
	requireShell(t)
	s := start(t, transport.StdioConfig{Command: script(t, echoServer)})
	for range 3 {
		if err := s.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
}

// TestStdioCancelledCallKeepsTheSession: one call giving up is a finding
// about that call, not the end of the connection.
//
// This assertion is the reverse of the one it replaces, which required a
// cancelled call to end the process. That was true of the first design,
// where the read happened inline and killing the server was the only way
// to free a goroutine blocked on the pipe — and it made a single slow
// method fatal to a whole run, while the same timeout over HTTP costs one
// finding. Custody did not move: Close still owns the process, which the
// second half of this test insists on.
func TestStdioCancelledCallKeepsTheSession(t *testing.T) {
	requireShell(t)
	// Answers the second request and ignores the first, so the timeout is
	// about one method rather than a server that is simply dead.
	s := start(t, transport.StdioConfig{Command: script(t, `
first=1
while IFS= read -r line; do
  if [ -n "$first" ]; then first=; continue; fi
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  printf '{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}\n' "$id"
done
`)})
	pid := s.PID()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := s.Call(ctx, "slow/method", nil, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Call = %v, want a deadline error", err)
	}
	if exited, _ := s.Exited(); exited {
		t.Fatal("a cancelled call killed the server")
	}

	// The connection is still usable, which is the whole point: the run
	// continues and reports the slow method rather than reporting nothing.
	var got struct {
		OK bool `json:"ok"`
	}
	if err := s.Call(context.Background(), "tools/list", nil, &got); err != nil {
		t.Fatalf("the connection did not survive the timeout: %v", err)
	}
	if !got.OK {
		t.Errorf("second call returned %+v", got)
	}

	// Custody is Close's, and it is not optional.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if alive(pid) {
		t.Errorf("process %d survived Close", pid)
	}
}

// TestStdioTimedOutCallDoesNotPoisonTheNextOne: the abandoned reply must
// not be handed to whoever calls next.
//
// This is the failure the id-matching reader exists to prevent. A server
// that answers late writes its reply after the caller has gone; if the
// next call read "the next message" it would decode the previous call's
// result and report it as its own, and the report would be wrong in a way
// nothing downstream could detect.
func TestStdioTimedOutCallDoesNotPoisonTheNextOne(t *testing.T) {
	requireShell(t)
	s := start(t, transport.StdioConfig{Command: script(t, `
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  m=$(printf '%s' "$line" | sed -n 's/.*"method":"\([^"]*\)".*/\1/p')
  case "$m" in
    slow/method) sleep 0.6 ;;
  esac
  printf '{"jsonrpc":"2.0","id":%s,"result":{"method":"%s"}}\n' "$id" "$m"
done
`)})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := s.Call(ctx, "slow/method", nil, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Call = %v, want a deadline error", err)
	}

	var got struct {
		Method string `json:"method"`
	}
	if err := s.Call(context.Background(), "tools/list", nil, &got); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if got.Method != "tools/list" {
		t.Errorf("the next call got the abandoned reply: %+v", got)
	}
}

func TestStdioEmptyCommand(t *testing.T) {
	if _, err := transport.StartStdio(context.Background(), transport.StdioConfig{}); err == nil {
		t.Error("an empty command started something")
	}
}

func TestStdioMissingCommand(t *testing.T) {
	_, err := transport.StartStdio(context.Background(), transport.StdioConfig{
		Command: filepath.Join(t.TempDir(), "definitely-not-here"),
	})
	if err == nil {
		t.Fatal("a missing command started")
	}
	if !strings.Contains(err.Error(), "start") {
		t.Errorf("error does not say what failed: %v", err)
	}
}

// TestStdioEnvIsNotInherited is a security property, not a convenience.
//
// A diagnostic that hands the server every variable the operator happens to
// have exported is how a credential reaches a program nobody audited.
func TestStdioEnvIsNotInherited(t *testing.T) {
	requireShell(t)
	t.Setenv("PASSMCP_STDIO_SECRET", "must-not-leak")
	s := start(t, transport.StdioConfig{Command: script(t, `
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  printf '{"jsonrpc":"2.0","id":%s,"result":{"secret":"%s"}}\n' "$id" "${PASSMCP_STDIO_SECRET:-absent}"
done
`)})
	var got struct {
		Secret string `json:"secret"`
	}
	if err := s.Call(context.Background(), "env", nil, &got); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if got.Secret != "absent" {
		t.Errorf("the server saw %q; a nil Env must not inherit the caller's", got.Secret)
	}
}

func TestStdioEnvIsPassedWhenGiven(t *testing.T) {
	requireShell(t)
	s := start(t, transport.StdioConfig{
		Command: script(t, `
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  printf '{"jsonrpc":"2.0","id":%s,"result":{"secret":"%s"}}\n' "$id" "${GIVEN:-absent}"
done
`),
		Env: []string{"GIVEN=yes"},
	})
	var got struct {
		Secret string `json:"secret"`
	}
	if err := s.Call(context.Background(), "env", nil, &got); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if got.Secret != "yes" {
		t.Errorf("an explicit Env did not reach the server: %q", got.Secret)
	}
}

// TestStdioConcurrentCalls: the framing matches by id and nothing else, so
// two calls in flight must not read one another's answers.
func TestStdioConcurrentCalls(t *testing.T) {
	requireShell(t)
	s := start(t, transport.StdioConfig{Command: script(t, echoServer)})

	const n = 12
	errs := make(chan error, n)
	for i := range n {
		go func(i int) {
			var got struct {
				Method string `json:"method"`
			}
			want := fmt.Sprintf("m%d", i)
			if err := s.Call(context.Background(), want, nil, &got); err != nil {
				errs <- err
				return
			}
			if got.Method != want {
				errs <- fmt.Errorf("call %d got %q", i, got.Method)
				return
			}
			errs <- nil
		}(i)
	}
	for range n {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
}

func TestStdioResetClearsSessionState(t *testing.T) {
	requireShell(t)
	s := start(t, transport.StdioConfig{Command: script(t, echoServer)})
	s.SetSessionID("abc")
	s.SetProtocolVersion("2025-11-25")
	s.Reset()
	if s.SessionID() != "" || s.ProtocolVersion() != "" {
		t.Errorf("Reset left %q / %q", s.SessionID(), s.ProtocolVersion())
	}
}

func TestStdioDialectRoundTrip(t *testing.T) {
	requireShell(t)
	s := start(t, transport.StdioConfig{Command: script(t, echoServer)})
	s.SetSessionID("abc")
	s.SetDialect(&transport.Stateless{ProtocolVersion: transport.V20260728})
	if s.Dialect().Version() != transport.V20260728 {
		t.Errorf("dialect = %q", s.Dialect().Version())
	}
	if s.SessionID() != "" {
		t.Error("a stateless dialect must clear the session id")
	}
}

// TestStdioPassEnvForwardsByName: a server that genuinely needs a
// credential is ordinary. Naming it is how the operator says so out loud,
// and is the difference between that and forwarding everything.
func TestStdioPassEnvForwardsByName(t *testing.T) {
	requireShell(t)
	t.Setenv("PASSMCP_WANTED", "yes")
	t.Setenv("PASSMCP_UNWANTED", "no")
	s := start(t, transport.StdioConfig{
		Command: script(t, `
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  printf '{"jsonrpc":"2.0","id":%s,"result":{"wanted":"%s","unwanted":"%s"}}\n' \
    "$id" "${PASSMCP_WANTED:-absent}" "${PASSMCP_UNWANTED:-absent}"
done
`),
		PassEnv: []string{"PASSMCP_WANTED"},
	})
	var got struct {
		Wanted   string `json:"wanted"`
		Unwanted string `json:"unwanted"`
	}
	if err := s.Call(context.Background(), "env", nil, &got); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if got.Wanted != "yes" {
		t.Errorf("a named variable did not reach the server: %q", got.Wanted)
	}
	if got.Unwanted != "absent" {
		t.Errorf("an unnamed variable reached the server: %q", got.Unwanted)
	}
}

// TestStdioBaseEnvReachesTheServer: an empty environment breaks almost
// every program for no security gain, so the harmless variables are passed.
//
// HOME rather than PATH, because POSIX sh invents a default PATH when it is
// unset — asserting on PATH measures the shell, not passmcp, and passes even
// when nothing was forwarded at all. This test was written that way first.
func TestStdioBaseEnvReachesTheServer(t *testing.T) {
	requireShell(t)
	t.Setenv("HOME", "/tmp/passmcp-home")
	s := start(t, transport.StdioConfig{Command: script(t, `
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  printf '{"jsonrpc":"2.0","id":%s,"result":{"home":"%s"}}\n' "$id" "${HOME:-absent}"
done
`)})
	var got struct {
		Home string `json:"home"`
	}
	if err := s.Call(context.Background(), "env", nil, &got); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if got.Home != "/tmp/passmcp-home" {
		t.Errorf("HOME did not reach the server: %q", got.Home)
	}
}

// TestStdioExplicitEmptyEnvIsHonoured: a caller who says "nothing" means
// nothing, and must not be given BaseEnv behind their back.
func TestStdioExplicitEmptyEnvIsHonoured(t *testing.T) {
	requireShell(t)
	t.Setenv("HOME", "/tmp/passmcp-home")
	s := start(t, transport.StdioConfig{
		Command: script(t, `
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  printf '{"jsonrpc":"2.0","id":%s,"result":{"home":"%s"}}\n' "$id" "${HOME:-absent}"
done
`),
		Env: []string{},
	})
	var got struct {
		Home string `json:"home"`
	}
	if err := s.Call(context.Background(), "env", nil, &got); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if got.Home != "absent" {
		t.Errorf("an explicitly empty Env still received %q", got.Home)
	}
}

// TestStdioStderrIsCompleteWhenTheProcessIsReaped pins the invariant that
// the pipe rewrite exists for.
//
// The first version used cmd.StderrPipe with a goroutine owning Wait, and
// Wait closes that pipe — so the drain raced the reap and usually lost on
// CI, producing "server process exited: exit status 3" with the line
// explaining it missing. cmd.Stderr is a writer now, so os/exec owns the
// copy and Wait joins it: once the process is reaped, stderr is whole.
//
// A large payload is written because a few bytes fit in the pipe buffer
// and would arrive even under the old race.
func TestStdioStderrIsCompleteWhenTheProcessIsReaped(t *testing.T) {
	requireShell(t)
	s := start(t, transport.StdioConfig{Command: script(t, `
i=0
while [ $i -lt 400 ]; do
  echo "diagnostic line $i padding padding padding padding padding" >&2
  i=$((i+1))
done
echo "fatal: the last line" >&2
exit 7
`)})

	err := s.Call(context.Background(), "tools/list", nil, nil)
	if err == nil {
		t.Fatal("a call to a server that exits succeeded")
	}
	if !errors.Is(err, transport.ErrProcessExited) {
		t.Fatalf("error is not ErrProcessExited: %v", err)
	}

	// Read immediately, with no sleep: the point is that no wait is needed.
	out := s.Stderr()
	if !strings.Contains(out, "fatal: the last line") {
		t.Errorf("the last line the server wrote is missing from stderr (%d bytes captured)", len(out))
	}
	if !strings.Contains(err.Error(), "the last line") {
		t.Errorf("the error does not carry it either: %v", err)
	}
	if exited, _ := s.Exited(); !exited {
		t.Error("the process was not reaped")
	}
}

// TestStdioExchangeSendsARawMessage: the conformance probes need to send a
// request the client API would never construct.
func TestStdioExchangeSendsARawMessage(t *testing.T) {
	requireShell(t)
	s := start(t, transport.StdioConfig{Command: script(t, `
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"no"}}\n' "$id"
done
`)})
	id := s.NextID()
	res, err := s.Exchange(context.Background(), transport.StdioExchange{
		Request: &transport.Request{JSONRPC: "2.0", ID: &id, Method: "passmcp/does_not_exist"},
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if res.Response == nil || res.Response.Error == nil {
		t.Fatalf("no error object in %s", res.Line)
	}
	if res.Response.Error.Code != -32601 {
		t.Errorf("code = %d", res.Response.Error.Code)
	}
	if res.Response.ID == nil || *res.Response.ID != id {
		t.Errorf("id = %v, want %d", res.Response.ID, id)
	}
}

// TestStdioExchangeReadsANullIDError: a parse error has no id to match.
//
// JSON-RPC requires a parse error to be reported with a null id — there is
// nothing to echo, because nothing parsed. A body-only exchange therefore
// waits for whatever comes next by construction, without being asked: an
// id-matching reader could never see this reply, and the probe that sends
// malformed input would report a timeout instead of the answer it got.
func TestStdioExchangeReadsANullIDError(t *testing.T) {
	requireShell(t)
	s := start(t, transport.StdioConfig{Command: script(t, `
while IFS= read -r line; do
  printf '{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}\n'
done
`)})
	res, err := s.Exchange(context.Background(), transport.StdioExchange{
		Body:       []byte(`{"jsonrpc":"2.0","id":1,"method":`),
		AnyMessage: true,
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if res.Response == nil || res.Response.Error == nil {
		t.Fatalf("no error object in %q", res.Line)
	}
	if res.Response.Error.Code != -32700 {
		t.Errorf("code = %d, want -32700", res.Response.Error.Code)
	}
}

// TestStdioExchangeRefusesANewline: a body with a newline in it is two
// messages, and the probe would be measuring something other than what it
// meant to send.
func TestStdioExchangeRefusesANewline(t *testing.T) {
	requireShell(t)
	s := start(t, transport.StdioConfig{Command: script(t, echoServer)})
	if _, err := s.Exchange(context.Background(), transport.StdioExchange{Body: []byte("{}\n{}")}); err == nil {
		t.Error("a two-line body was sent as one message")
	}
}

// TestStdioNoiseNamesTheStrayLine: "it hangs" is not a diagnosis.
//
// A stdio server that prints anything to stdout has broken the transport,
// and this is by far the most common way one is broken. Keeping the line
// is the difference between a report that says which line and a report
// that says the server did not answer.
func TestStdioNoiseNamesTheStrayLine(t *testing.T) {
	requireShell(t)
	s := start(t, transport.StdioConfig{Command: script(t, `
while IFS= read -r line; do
  echo "Listening on stdio..."
done
`)})
	if err := s.Call(context.Background(), "tools/list", nil, nil); err == nil {
		t.Fatal("a stray line was accepted")
	}
	n, sample := s.Noise()
	if n != 1 {
		t.Errorf("Noise counted %d lines, want 1", n)
	}
	if sample != "Listening on stdio..." {
		t.Errorf("sample = %q", sample)
	}
}

// TestStdioExchangeAnyMessageSeesAMismatchedID is why AnyMessage exists.
//
// "The response id matches the request id" is one of the checks, so the
// probe has to be able to observe a server that answers with the wrong
// one. Matching by id cannot: the reply belongs to no outstanding call, so
// it is dropped as unsolicited and the probe times out — reporting that
// the server did not answer, when in fact it answered incorrectly. Those
// are different findings, and the second is the true one.
func TestStdioExchangeAnyMessageSeesAMismatchedID(t *testing.T) {
	requireShell(t)
	s := start(t, transport.StdioConfig{Command: script(t, `
while IFS= read -r line; do
  printf '{"jsonrpc":"2.0","id":9999,"result":{}}\n'
done
`)})
	id := s.NextID()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := s.Exchange(ctx, transport.StdioExchange{
		Request:    &transport.Request{JSONRPC: "2.0", ID: &id, Method: "tools/list"},
		AnyMessage: true,
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if res.Response == nil || res.Response.ID == nil {
		t.Fatalf("no response with an id in %q", res.Line)
	}
	if *res.Response.ID == id {
		t.Fatalf("the fixture echoed the id; it is meant not to")
	}
}
