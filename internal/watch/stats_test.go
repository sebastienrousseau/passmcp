// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package watch

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net"
	"net/url"
	"os"
	"syscall"
	"testing"
	"time"

	"satellion.com/passmcp"
	"satellion.com/passmcp/auth"
	"satellion.com/passmcp/internal/engine"
	"satellion.com/passmcp/transport"
)

// timeoutErr is a net.Error that timed out, the shape an http.Client
// deadline produces.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// TestClassifySortsFailuresByWhoseProblemTheyAre. An availability figure
// that lumps a DNS outage, an expired credential and a server answering
// garbage into one "error" bucket tells the reader nothing they can act on.
func TestClassifySortsFailuresByWhoseProblemTheyAre(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status Status
		kind   string
	}{
		{"nil", nil, StatusOK, ""},
		{"deadline", context.DeadlineExceeded, StatusTimeout, "deadline"},
		{"client timeout", &url.Error{Op: "Post", URL: "http://x", Err: timeoutErr{}}, StatusTimeout, "timeout"},
		{"os deadline", fmt.Errorf("read: %w", os.ErrDeadlineExceeded), StatusTimeout, "timeout"},
		{"login", &engine.LoginRequiredError{Message: "server requires a user login"}, StatusAuth, "login_required"},
		{"token endpoint", &auth.TokenError{StatusCode: 400, Code: "invalid_client"}, StatusAuth, "token_endpoint"},
		{"scope", &auth.InsufficientScopeError{Scope: "x"}, StatusAuth, "insufficient_scope"},
		{"url policy", &auth.PolicyError{Kind: "token endpoint", URL: "http://x", Reason: "plain http"}, StatusAuth, "url_policy"},
		{"401", &transport.HTTPStatusError{StatusCode: 401}, StatusAuth, "http_401"},
		{"403", fmt.Errorf("list: %w", &transport.HTTPStatusError{StatusCode: 403}), StatusAuth, "http_403"},
		{"rpc over 400", &transport.HTTPStatusError{StatusCode: 400, RPCError: &transport.RPCError{Code: -32600}}, StatusProtocol, "jsonrpc_-32600"},
		{"rpc", fmt.Errorf("tools/list: %w", &transport.RPCError{Code: -32601, Message: "no"}), StatusProtocol, "jsonrpc_-32601"},
		{"version", &transport.UnsupportedVersionError{Requested: "x"}, StatusProtocol, "unsupported_version"},
		{"capability", &transport.MissingCapabilityError{}, StatusProtocol, "missing_capability"},
		{"headers", &transport.HeaderMismatchError{Message: "x"}, StatusProtocol, "header_mismatch"},
		{"pagination", passmcp.ErrPaginationCycle, StatusProtocol, "pagination"},
		{"stream", transport.ErrStreamTooLarge, StatusProtocol, "stream_too_large"},
		{"json", &json.SyntaxError{}, StatusProtocol, "malformed_json"},
		{"503", &transport.HTTPStatusError{StatusCode: 503}, StatusTransport, "http_503"},
		{"dns", &url.Error{Op: "Post", URL: "http://x", Err: &net.DNSError{Err: "no such host", Name: "x"}}, StatusTransport, "dns"},
		{"refused", &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, StatusTransport, "connection_refused"},
		{"reset", &net.OpError{Op: "read", Err: os.NewSyscallError("read", syscall.ECONNRESET)}, StatusTransport, "connection_reset"},
		{"tls", &url.Error{Op: "Post", URL: "https://x", Err: x509.UnknownAuthorityError{}}, StatusTransport, "tls"},
		{"hostname", x509.HostnameError{Host: "x"}, StatusTransport, "tls"},
		{"eof", fmt.Errorf("read: %w", io.ErrUnexpectedEOF), StatusTransport, "eof"},
		{"net", &net.OpError{Op: "dial", Err: errors.New("no route")}, StatusTransport, "network"},
		{"other", errors.New("something odd"), StatusTransport, "other"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, kind := Classify(c.err)
			if st != c.status || kind != c.kind {
				t.Errorf("Classify(%v) = %s/%s, want %s/%s", c.err, st, kind, c.status, c.kind)
			}
		})
	}
}

// TestSummaryReportsAvailabilityAndLatency is the arithmetic a reader
// will quote, so it is checked by hand rather than trusted.
func TestSummaryReportsAvailabilityAndLatency(t *testing.T) {
	sum := mixedRun()
	if sum.Pulses != 106 || sum.OK != 101 || sum.Failed != 5 {
		t.Fatalf("counts = %+v", sum)
	}
	if math.Abs(sum.SuccessRate-101.0/106.0) > 1e-9 {
		t.Errorf("success rate = %v", sum.SuccessRate)
	}
	// Latency is over answered pulses only: a timeout's thirty seconds is
	// an availability fact, not a latency sample.
	want := Latency{P50: 50, P95: 95, P99: 99, Samples: 101}
	if sum.Latency != want {
		t.Errorf("latency = %+v, want %+v", sum.Latency, want)
	}
	if sum.WorstFailureStreak != 3 {
		t.Errorf("worst streak = %d, want 3", sum.WorstFailureStreak)
	}
}

// TestSummaryBreaksFailuresDown by class and by kind.
func TestSummaryBreaksFailuresDown(t *testing.T) {
	sum := mixedRun()
	wantStatus := map[string]int{"ok": 101, "transport_error": 2, "timeout": 1, "auth_error": 1, "protocol_error": 1}
	if !maps.Equal(sum.ByStatus, wantStatus) {
		t.Errorf("by_status = %v, want %v", sum.ByStatus, wantStatus)
	}
	wantKind := map[string]int{"connection_refused": 2, "deadline": 1, "http_401": 1, "jsonrpc_-32601": 1}
	if !maps.Equal(sum.ByErrorKind, wantKind) {
		t.Errorf("by_error_kind = %v, want %v", sum.ByErrorKind, wantKind)
	}
}

// mixedRun is a hundred answered pulses of 1..100ms, then three failures
// in a row, one success and two more failures.
func mixedRun() Summary {
	var s Stats
	for i := 1; i <= 100; i++ {
		s.Observe(StatusOK, "", time.Duration(i)*time.Millisecond)
	}
	s.Observe(StatusTransport, "connection_refused", time.Millisecond)
	s.Observe(StatusTransport, "connection_refused", time.Millisecond)
	s.Observe(StatusTimeout, "deadline", 30*time.Second)
	s.Observe(StatusOK, "", 50*time.Millisecond)
	s.Observe(StatusAuth, "http_401", time.Millisecond)
	s.Observe(StatusProtocol, "jsonrpc_-32601", time.Millisecond)
	return s.Summary()
}

// TestAnEmptySummaryIsNotANumberNobodyCanRead: a watcher stopped before
// its first pulse must still serialise.
func TestAnEmptySummaryIsNotANumberNobodyCanRead(t *testing.T) {
	var s Stats
	sum := s.Summary()
	if sum.Pulses != 0 || sum.SuccessRate != 0 || sum.Latency.P99 != 0 {
		t.Errorf("empty summary = %+v", sum)
	}
	if _, err := json.Marshal(sum); err != nil {
		t.Fatalf("empty summary does not serialise: %v", err)
	}
}

// TestLatencySamplesAreBounded, because a watcher runs for months and its
// memory must not grow with them.
func TestLatencySamplesAreBounded(t *testing.T) {
	var s Stats
	for i := range maxLatencySamples + 10 {
		s.Observe(StatusOK, "", time.Duration(i)*time.Microsecond)
	}
	sum := s.Summary()
	if sum.Latency.Samples != maxLatencySamples {
		t.Errorf("samples = %d, want %d", sum.Latency.Samples, maxLatencySamples)
	}
	if sum.Pulses != maxLatencySamples+10 {
		t.Errorf("the pulse count must still cover every pulse, got %d", sum.Pulses)
	}
	// The oldest were the ones dropped: the smallest sample left is the
	// eleventh observed.
	if got := s.latencies[0]; math.Abs(got-0.010) > 1e-9 {
		t.Errorf("oldest retained sample = %vms, want 0.010 (the eleventh observed)", got)
	}
}

// TestPercentileIsNearestRank on the small inputs where interpolation and
// nearest-rank disagree, so the documented method is the one used.
func TestPercentileIsNearestRank(t *testing.T) {
	if got := percentile([]float64{1}, 0.99); got != 1 {
		t.Errorf("single sample p99 = %v", got)
	}
	if got := percentile([]float64{1, 2}, 0.5); got != 1 {
		t.Errorf("p50 of two = %v, want the lower (nearest rank)", got)
	}
	if got := percentile(nil, 0.5); got != 0 {
		t.Errorf("p50 of none = %v", got)
	}
}
