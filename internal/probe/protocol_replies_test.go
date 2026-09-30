// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"strings"
	"testing"

	"satellion.com/passmcp/internal/creds"
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
