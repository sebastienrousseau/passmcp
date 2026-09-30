// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package watch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"slices"
	"strconv"
	"syscall"
	"time"

	"satellion.com/passmcp"
	"satellion.com/passmcp/auth"
	"satellion.com/passmcp/internal/engine"
	"satellion.com/passmcp/transport"
)

// Availability comes from the pulses the watcher already takes. It adds no
// request: the pulse is timed and its outcome sorted, and that is all. A
// monitor that sent extra traffic to measure the server would be the load
// generator MinInterval exists to prevent.

// Status is the class of a pulse's outcome: whose problem a failure is.
type Status string

const (
	// StatusOK is a pulse that listed the catalogue.
	StatusOK Status = "ok"
	// StatusProtocol is a server that answered, but not with MCP it could
	// be understood by: a JSON-RPC error, a malformed body, a version it
	// refused.
	StatusProtocol Status = "protocol_error"
	// StatusTransport is a server that could not be reached, or answered
	// with an HTTP failure: DNS, a refused or reset connection, TLS, a 5xx.
	StatusTransport Status = "transport_error"
	// StatusAuth is a credential problem: a 401 or 403, a token endpoint
	// that refused, a login that has not happened yet.
	StatusAuth Status = "auth_error"
	// StatusTimeout is a pulse that ran out of time.
	StatusTimeout Status = "timeout"
)

// classifier recognises one family of errors.
type classifier func(error) (Status, string, bool)

// classifiers are tried in order. Timeouts first, because a timeout is
// usually wrapped in a transport error and "it timed out" is the more
// useful statement; auth before protocol, because a 401 is an HTTP status
// that carries no JSON-RPC body.
var classifiers = []classifier{classifyTimeout, classifyAuth, classifyProtocol, classifyHTTP, classifyNetwork}

// Classify sorts an error from a pulse into a Status and a short kind, such
// as transport_error/connection_refused or protocol_error/jsonrpc_-32601.
// A nil error is StatusOK with no kind. An error nothing recognises is a
// transport error of kind "other": the pulse did not get an MCP answer,
// which is what availability measures.
func Classify(err error) (Status, string) {
	if err == nil {
		return StatusOK, ""
	}
	for _, c := range classifiers {
		if st, kind, ok := c(err); ok {
			return st, kind
		}
	}
	return StatusTransport, "other"
}

func classifyTimeout(err error) (Status, string, bool) {
	if errors.Is(err, context.DeadlineExceeded) {
		return StatusTimeout, "deadline", true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return StatusTimeout, "timeout", true
	}
	return "", "", false
}

func classifyAuth(err error) (Status, string, bool) {
	var (
		login  *engine.LoginRequiredError
		token  *auth.TokenError
		scope  *auth.InsufficientScopeError
		policy *auth.PolicyError
		status *transport.HTTPStatusError
	)
	switch {
	case errors.As(err, &login):
		return StatusAuth, "login_required", true
	case errors.As(err, &token):
		return StatusAuth, "token_endpoint", true
	case errors.As(err, &scope):
		return StatusAuth, "insufficient_scope", true
	case errors.As(err, &policy):
		return StatusAuth, "url_policy", true
	case errors.As(err, &status) && (status.StatusCode == 401 || status.StatusCode == 403):
		return StatusAuth, "http_" + strconv.Itoa(status.StatusCode), true
	}
	return "", "", false
}

// protocolSentinels are the protocol failures that are values, not types.
var protocolSentinels = []struct {
	err  error
	kind string
}{
	{passmcp.ErrPaginationCycle, "pagination"},
	{transport.ErrStreamTooLarge, "stream_too_large"},
}

func classifyProtocol(err error) (Status, string, bool) {
	var (
		version *transport.UnsupportedVersionError
		capab   *transport.MissingCapabilityError
		header  *transport.HeaderMismatchError
		syntax  *json.SyntaxError
	)
	switch {
	case errors.As(err, &version):
		return StatusProtocol, "unsupported_version", true
	case errors.As(err, &capab):
		return StatusProtocol, "missing_capability", true
	case errors.As(err, &header):
		return StatusProtocol, "header_mismatch", true
	case errors.As(err, &syntax):
		return StatusProtocol, "malformed_json", true
	}
	if rpc := rpcErrorIn(err); rpc != nil {
		return StatusProtocol, "jsonrpc_" + strconv.Itoa(rpc.Code), true
	}
	for _, s := range protocolSentinels {
		if errors.Is(err, s.err) {
			return StatusProtocol, s.kind, true
		}
	}
	return "", "", false
}

// rpcErrorIn finds a JSON-RPC error, bare or carried by an HTTP status.
func rpcErrorIn(err error) *transport.RPCError {
	var rpc *transport.RPCError
	if errors.As(err, &rpc) {
		return rpc
	}
	var status *transport.HTTPStatusError
	if errors.As(err, &status) {
		return status.RPCError
	}
	return nil
}

func classifyHTTP(err error) (Status, string, bool) {
	var status *transport.HTTPStatusError
	if errors.As(err, &status) {
		return StatusTransport, "http_" + strconv.Itoa(status.StatusCode), true
	}
	return "", "", false
}

// networkKinds are checked in order; the first that matches names the
// failure. Specific before general: a refused connection is also a
// *net.OpError.
var networkKinds = []struct {
	kind  string
	match func(error) bool
}{
	{"dns", func(err error) bool { var e *net.DNSError; return errors.As(err, &e) }},
	{"connection_refused", func(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }},
	{"connection_reset", func(err error) bool { return errors.Is(err, syscall.ECONNRESET) }},
	{"tls", isTLSError},
	{"eof", func(err error) bool { return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) }},
	{"network", func(err error) bool { var e *net.OpError; return errors.As(err, &e) }},
}

func classifyNetwork(err error) (Status, string, bool) {
	for _, k := range networkKinds {
		if k.match(err) {
			return StatusTransport, k.kind, true
		}
	}
	return "", "", false
}

// isTLSError recognises a handshake or certificate failure.
func isTLSError(err error) bool {
	var (
		unknown  x509.UnknownAuthorityError
		hostname x509.HostnameError
		invalid  x509.CertificateInvalidError
		verify   *tls.CertificateVerificationError
		record   tls.RecordHeaderError
	)
	return errors.As(err, &unknown) || errors.As(err, &hostname) || errors.As(err, &invalid) ||
		errors.As(err, &verify) || errors.As(err, &record)
}

// maxLatencySamples bounds the latencies kept for percentiles: about five
// weeks of pulses at MinInterval. Beyond it the oldest are dropped, so the
// percentiles describe the most recent pulses and memory does not grow
// with the life of the process.
const maxLatencySamples = 100_000

// Stats accumulates pulse outcomes. The zero value is ready to use. It is
// not safe for concurrent use; a watcher takes one pulse at a time.
type Stats struct {
	pulses, ok    int
	streak, worst int
	byStatus      map[Status]int
	byKind        map[string]int
	latencies     []float64 // milliseconds, answered pulses only, oldest first
}

// Observe records one pulse.
func (s *Stats) Observe(st Status, kind string, latency time.Duration) {
	if s.byStatus == nil {
		s.byStatus, s.byKind = map[Status]int{}, map[string]int{}
	}
	s.pulses++
	s.byStatus[st]++
	if st != StatusOK {
		s.streak++
		s.worst = max(s.worst, s.streak)
		s.byKind[kind]++
		return
	}
	s.ok++
	s.streak = 0
	if len(s.latencies) == maxLatencySamples {
		s.latencies = append(s.latencies[:0], s.latencies[1:]...)
	}
	s.latencies = append(s.latencies, float64(latency)/float64(time.Millisecond))
}

// Latency is the latency distribution of answered pulses, in milliseconds.
type Latency struct {
	// P50, P95 and P99 are nearest-rank percentiles.
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
	P99 float64 `json:"p99"`
	// Samples is how many pulses they are computed over: the answered
	// ones, at most the most recent 100,000.
	Samples int `json:"samples"`
}

// Summary is what a watch run amounted to, for availability.
type Summary struct {
	// Pulses is how many were taken to completion.
	Pulses int `json:"pulses"`
	// OK is how many listed the catalogue, drift or not: the server
	// answered.
	OK int `json:"ok"`
	// Failed is how many did not.
	Failed int `json:"failed"`
	// SuccessRate is OK / Pulses, between 0 and 1; 0 when there were no
	// pulses.
	SuccessRate float64 `json:"success_rate"`
	// Latency is over answered pulses only. A timeout's duration is an
	// availability fact, not a latency sample, and mixing them would make
	// the p99 a measure of the client's deadline.
	Latency Latency `json:"latency_ms"`
	// WorstFailureStreak is the longest run of consecutive failed pulses.
	WorstFailureStreak int `json:"worst_failure_streak"`
	// ByStatus counts pulses per Status.
	ByStatus map[string]int `json:"by_status"`
	// ByErrorKind counts failed pulses per error kind.
	ByErrorKind map[string]int `json:"by_error_kind,omitempty"`
}

// Summary computes the summary of everything observed so far.
func (s *Stats) Summary() Summary {
	out := Summary{
		Pulses: s.pulses, OK: s.ok, Failed: s.pulses - s.ok,
		WorstFailureStreak: s.worst,
		ByStatus:           map[string]int{},
	}
	if s.pulses > 0 {
		out.SuccessRate = float64(s.ok) / float64(s.pulses)
	}
	for st, n := range s.byStatus {
		out.ByStatus[string(st)] = n
	}
	if len(s.byKind) > 0 {
		out.ByErrorKind = map[string]int{}
		for k, n := range s.byKind {
			out.ByErrorKind[k] = n
		}
	}
	sorted := slices.Clone(s.latencies)
	slices.Sort(sorted)
	out.Latency = Latency{
		P50: percentile(sorted, 0.50), P95: percentile(sorted, 0.95), P99: percentile(sorted, 0.99),
		Samples: len(sorted),
	}
	return out
}

// Sentence says the summary in one line for a person.
func (s Summary) Sentence() string {
	return fmt.Sprintf("%d of %d pulse(s) answered (%.1f%%)", s.OK, s.Pulses, 100*s.SuccessRate)
}

// percentile is the nearest-rank percentile of sorted: the smallest sample
// at or above which a fraction q of the samples lie. Zero for no samples.
func percentile(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(math.Ceil(q*float64(len(sorted)))) - 1
	return sorted[max(0, min(i, len(sorted)-1))]
}
