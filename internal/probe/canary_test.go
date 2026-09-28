// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"strings"
	"testing"

	"satellion.com/passmcp/internal/canary"
	"satellion.com/passmcp/internal/telemetry"
)

// TestCanariesAreSilentWhenNotPlanted: this changes where the server's
// HOME points, so it is opt-in, and a run that did not ask says nothing.
func TestCanariesAreSilentWhenNotPlanted(t *testing.T) {
	s := &Session{Opts: Options{Recorder: &telemetry.Recorder{}}}
	if got := checkCanaries(s); len(got) != 0 {
		t.Fatalf("want no findings without decoys, got %+v", got)
	}
}

// TestCanariesSayWhenTheyCouldNotBePlanted rather than reporting a clean
// result from a witness that never existed.
func TestCanariesSayWhenTheyCouldNotBePlanted(t *testing.T) {
	s := &Session{
		Opts:      Options{Recorder: &telemetry.Recorder{}, PlantCanaries: true},
		canaryErr: "read-only file system",
	}
	out := checkCanaries(s)
	if len(out) != 1 || out[0].Status != Info {
		t.Fatalf("want one informational finding, got %+v", out)
	}
	if !strings.Contains(out[0].Detail, "read-only file system") {
		t.Errorf("the finding does not carry the reason: %q", out[0].Detail)
	}
}

// TestCredentialProbeSkipsWhenAccessTimesDoNotWork is the branch that
// keeps this honest, and the reason the instrument measures itself. On a
// filesystem that does not record reads, "nothing was opened" is a
// statement passmcp is not entitled to make.
func TestCredentialProbeSkipsWhenAccessTimesDoNotWork(t *testing.T) {
	cn, err := canary.Seed(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cn.Close() })

	s := &Session{Opts: Options{Recorder: &telemetry.Recorder{}, PlantCanaries: true}, Canary: cn}
	f := byFindingID(checkCanaries(s))["fs.credential_probe"]

	usable, why := cn.AtimeUsable()
	if usable {
		// A filesystem that does record reads: nothing was opened here.
		if f.Status != Pass {
			t.Fatalf("want a pass where access times work, got %s %q", f.Status, f.Detail)
		}
		return
	}
	if f.Status != Skip {
		t.Fatalf("want a skip where access times do not work, got %s %q", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, "cannot tell") {
		t.Errorf("the skip does not say what it could not do: %q", f.Detail)
	}
	if why != "" && !strings.Contains(f.Detail, "access times") {
		t.Errorf("the skip does not carry the reason: %q", f.Detail)
	}
	// And it has to point at the witness that still works.
	if !strings.Contains(f.Detail, "fs.canary_exfiltrated") {
		t.Errorf("the skip does not say what still applies: %q", f.Detail)
	}
}

// TestExfiltrationIsFoundInWhatTheServerSent: a server that hands a
// planted key back to passmcp has exfiltrated it to the only other party in
// the conversation.
func TestExfiltrationIsFoundInWhatTheServerSent(t *testing.T) {
	cn, err := canary.Seed(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cn.Close() })

	s := &Session{Opts: Options{Recorder: telemetry.New(), PlantCanaries: true}, Canary: cn}

	// Nothing has moved yet.
	if f := byFindingID(checkCanaries(s))["fs.canary_exfiltrated"]; f.Status != Pass {
		t.Fatalf("a clean run did not pass: %+v", f)
	}

	// Now the server says one of the markers out loud, on the pipe, which
	// is where it is noticed as it arrives.
	marker := cn.Markers()[0]
	s.noteCanaries([]byte(`{"result":{"key":"`+marker+`"}}`), "sent back to passmcp over the pipe")

	f := byFindingID(checkCanaries(s))["fs.canary_exfiltrated"]
	if f.Status != Fail {
		t.Fatalf("a marker in what the server sent was not reported: %+v", f)
	}
	if f.Severity != Critical {
		t.Errorf("severity = %v, want Critical", f.Severity)
	}
	if !strings.Contains(f.Detail, cn.MarkerName(marker)) {
		t.Errorf("the finding does not name the file it came from: %q", f.Detail)
	}
	// The marker itself must not be echoed: it is the evidence, not the
	// message, and a report is a thing people paste into tickets.
	if strings.Contains(f.Detail, marker) {
		t.Errorf("the finding repeats the marker verbatim: %q", f.Detail)
	}
}

// TestCanaryCatchesAServerStealingTheKey is the roadmap's own proof, run
// end to end: a server that reads the decoy key and posts it to a third
// host must produce the witness.
//
// Everything about this fixture is otherwise impeccable — it handshakes,
// serves a catalogue, exits cleanly — so no other check in the report has
// anything to say about it.
func TestCanaryCatchesAServerStealingTheKey(t *testing.T) {
	// The collector deliberately does not resolve, for the reason the
	// egress test gives: Go never proxies a loopback address, so a
	// httptest server on 127.0.0.1 would bypass the proxy and the body
	// would never be scanned. The proxy reads the body before it tries
	// the connection, so the theft is caught either way -- which is also
	// true of a real exfiltration to a host that happens to be down.
	_, fs := runStdioWatched(t, "steals-canary", "http://collector.passmcp-fixture.invalid/drop")

	f := fs["fs.canary_exfiltrated"]
	if f.Status != Fail {
		t.Fatalf("a server that posted the decoy key was not caught: %+v", f)
	}
	if !strings.Contains(f.Detail, ".ssh/id_rsa") {
		t.Errorf("the finding does not name the file: %q", f.Detail)
	}

	// The server itself did everything else right, which is the point.
	if a := fs["stdio.alive"]; a.Status != Pass {
		t.Errorf("the fixture was supposed to be a well-behaved server: %+v", a)
	}
}

// TestCanaryCatchesAServerReadingTheKey is the weaker witness, and only
// where the filesystem records reads at all.
func TestCanaryCatchesAServerReadingTheKey(t *testing.T) {
	probe, err := canary.Seed(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	usable, why := probe.AtimeUsable()
	_ = probe.Close()
	if !usable {
		t.Skipf("this filesystem cannot record the witness: %s", why)
	}

	_, fs := runStdioWatched(t, "reads-canary", "")
	f := fs["fs.credential_probe"]
	if f.Status != Fail {
		t.Fatalf("a server that read the decoy key was not caught: %+v", f)
	}
	if !strings.Contains(f.Detail, ".ssh/id_rsa") {
		t.Errorf("the finding does not name the file: %q", f.Detail)
	}
}
