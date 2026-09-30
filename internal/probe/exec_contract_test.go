// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"testing"

	"satellion.com/passmcp/internal/creds"
)

// throughExecution runs every phase up to execution against f.
func throughExecution(t *testing.T, f *fakeServer) map[string]Finding {
	t.Helper()
	f.acceptAnyToken = true
	_, fs := run(t, f, &creds.Credentials{Mode: creds.ModeBearer, Token: "tok-1234"}, func(o *Options) {
		o.Only = []string{"net", "discovery", "auth", "handshake", "catalog", "execution"}
	})
	return fs
}

func TestResourceReadURI(t *testing.T) {
	// The fake answers under the URI it was asked for, and the pass cites
	// the read.
	fs := throughExecution(t, newFakeServer(t))
	expect(t, fs, "execution.resources.uri", Pass, "1 read")
	if len(fs["execution.resources.uri"].Evidence) == 0 {
		t.Error("a pass must cite the read it came from")
	}

	// Contents filed under another URI warn, naming both and citing the
	// read that showed it.
	f := newFakeServer(t)
	f.q.readURI = "fake://doc/other"
	fs = throughExecution(t, f)
	expect(t, fs, "execution.resources.uri", Warn, "fake://doc/1 returned fake://doc/other")
	if len(fs["execution.resources.uri"].Evidence) == 0 {
		t.Error("the warning must cite the read")
	}

	// Contents with no uri at all.
	f = newFakeServer(t)
	f.q.readURI = "-"
	expect(t, throughExecution(t, f), "execution.resources.uri", Warn, "no uri")

	// Nothing came back to compare.
	f = newFakeServer(t)
	f.q.readFail = true
	expect(t, throughExecution(t, f), "execution.resources.uri", Skip, "no resource read returned contents")
	f = newFakeServer(t)
	f.q.resourcesEmpty = true
	expect(t, throughExecution(t, f), "execution.resources.uri", Skip, "no resource read returned contents")
}
