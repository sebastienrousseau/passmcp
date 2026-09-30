// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"fmt"
	"strings"
	"testing"

	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/telemetry"
)

var replyBearer = &creds.Credentials{Mode: creds.ModeBearer, Token: "tok-1234"}

// replyPhases is the smallest run that reaches the protocol phase with a
// session.
func replyPhases(o *Options) {
	o.Only = []string{"net", "discovery", "auth", "handshake", "protocol"}
}

// An HTML page where the MCP endpoint should be is reported for what it is
// at the first request that reads a reply, instead of as the JSON
// decoder's complaint about a '<'.
func TestLoginPageIsNamedAtInitialize(t *testing.T) {
	f := newFakeServer(t)
	f.acceptAnyToken = true
	f.q.loginPage = true
	s, fs := run(t, f, replyBearer, replyPhases)
	expect(t, fs, "handshake.initialize", Fail, "got text/html; likely a login")
	if d := fs["handshake.initialize"].Detail; strings.Contains(d, "invalid character") {
		t.Errorf("detail still leads with the decoder's error: %q", d)
	}
	if s.Blocked() == "" {
		t.Error("a login page at initialize must block the run")
	}
}

// evidenceMethod is the JSON-RPC method of the one request a finding
// cites, so a test can prove the finding points at the exchange it judged.
func evidenceMethod(t *testing.T, s *Session, f Finding) string {
	t.Helper()
	if len(f.Evidence) != 1 {
		t.Fatalf("%s cites %v, want exactly one request", f.ID, f.Evidence)
	}
	var seq int
	if _, err := fmt.Sscanf(f.Evidence[0], "req#%d", &seq); err != nil {
		t.Fatalf("%s evidence %q: %v", f.ID, f.Evidence[0], err)
	}
	for _, e := range s.Opts.Recorder.Events() {
		if e.Seq == seq && e.RPC != nil {
			return e.RPC.Method
		}
	}
	t.Fatalf("%s cites req#%d, which is not a recorded JSON-RPC exchange", f.ID, seq)
	return ""
}

// The acknowledgement the handshake already received is the evidence: no
// second notification is sent to judge the first.
func TestNotificationAck(t *testing.T) {
	f := newFakeServer(t)
	f.acceptAnyToken = true
	s, fs := run(t, f, replyBearer, replyPhases)
	expect(t, fs, "protocol.notification_ack", Pass, "202 Accepted, empty body")
	if m := evidenceMethod(t, s, fs["protocol.notification_ack"]); m != "notifications/initialized" {
		t.Errorf("protocol.notification_ack cites a %s exchange", m)
	}
	notes := 0
	for _, e := range s.Opts.Recorder.Events() {
		if e.RPC != nil && e.RPC.Method == "notifications/initialized" {
			notes++
		}
	}
	if notes != 1 {
		t.Errorf("%d notifications/initialized were sent; the check must reuse the handshake's", notes)
	}

	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   string
	}{
		// The body arrives chunked, after the header was flushed, so the
		// size is read rather than taken from a Content-Length.
		{"body on 202", 202, `{"ok":true}`, "202 Accepted with a body of 11 bytes"},
		{"200 with a body", 200, `{"jsonrpc":"2.0"}`, "HTTP 200 with a body of 17 bytes"},
		{"200 empty", 200, "", "HTTP 200 with no body"},
		{"204", 204, "", "HTTP 204 with no body"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeServer(t)
			f.acceptAnyToken = true
			f.q.notifyStatus, f.q.notifyBody = tc.status, tc.body
			_, fs := run(t, f, replyBearer, replyPhases)
			expect(t, fs, "protocol.notification_ack", Fail, tc.want)
			if got := fs["protocol.notification_ack"]; got.Severity != Minor || !strings.Contains(got.Advice, "202 Accepted") {
				t.Errorf("severity %q, advice %q", got.Severity, got.Advice)
			}
		})
	}
}

// Where the exchange never happened there is nothing to judge, and the
// finding says why rather than passing.
func TestNotificationAckSkips(t *testing.T) {
	s := runStateless(t, statelessFake(t, statelessOpts{}), nil)
	f, ok := findingByID(s, "protocol.notification_ack")
	if !ok || f.Status != Skip || !strings.Contains(f.Detail, "no initialize handshake") {
		t.Errorf("stateless: %+v", f)
	}

	// A recording too short to still hold the handshake.
	fk := newFakeServer(t)
	fk.acceptAnyToken = true
	_, fs := run(t, fk, replyBearer, func(o *Options) {
		replyPhases(o)
		o.Recorder.MaxEvents = 2
	})
	expect(t, fs, "protocol.notification_ack", Skip, "no notifications/initialized")
}

// The verdicts no fake can reach through a completed handshake, because a
// notification that fails or is refused fails initialize first.
func TestAckVerdictRefusedOrFailed(t *testing.T) {
	s := &Session{Opts: Options{Recorder: telemetry.New()}}
	got := ackVerdict(s.check("protocol.notification_ack", "t"), telemetry.Event{Status: 400})
	if got.Status != Fail || got.Severity != Major || !strings.Contains(got.Detail, "HTTP 400") {
		t.Errorf("refused: %+v", got)
	}
	got = ackVerdict(s.check("protocol.notification_ack", "t"), telemetry.Event{Error: "connection reset"})
	if got.Status != Info || !strings.Contains(got.Detail, "connection reset") {
		t.Errorf("failed: %+v", got)
	}
}
