// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"strings"
	"testing"

	"satellion.com/passmcp/transport"
)

// A conformant server on the stateless revision answers -32601 to both
// methods the revision removed, and that is the pass.
func TestRemovedMethodsAreGone(t *testing.T) {
	s := runStateless(t, statelessFake(t, statelessOpts{}), nil)
	f, ok := findingByID(s, "protocol.deprecated_features")
	if !ok {
		t.Fatal("protocol.deprecated_features is missing")
	}
	if f.Status != Pass {
		t.Errorf("status = %s: %s", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, "are gone") {
		t.Errorf("detail does not say what was checked: %q", f.Detail)
	}
}

// Still serving them without declaring the older revisions is the finding:
// the handlers are there and nothing tells a client they may be used, so the
// only callers left are stale software and whoever is enumerating.
func TestRemovedMethodsStillServedUndeclared(t *testing.T) {
	s := runStateless(t, statelessFake(t, statelessOpts{serveRemoved: true}), nil)
	f, ok := findingByID(s, "protocol.deprecated_features")
	if !ok {
		t.Fatal("protocol.deprecated_features is missing")
	}
	if f.Status != Warn {
		t.Fatalf("status = %s: %s", f.Status, f.Detail)
	}
	for _, want := range []string{"initialize", "ping", "no handshake revision"} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("detail does not mention %q: %q", want, f.Detail)
		}
	}
	// The evidence has to name the mechanism, not only the method: "ping" on
	// its own reads as a spelling complaint.
	// Named by mechanism, not only by method: "ping" on its own reads as a
	// spelling complaint. The request references the recorder appends come
	// after, so this is a contains rather than a length.
	ev := strings.Join(f.Evidence, " ")
	for _, want := range []string{"initialize (the opening handshake)", "ping (liveness)"} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence does not name %q: %v", want, f.Evidence)
		}
	}
}

// Serving both generations is legitimate. supportedVersions is how a server
// says so, and saying so is what turns the finding into a pass — otherwise
// passmcp would be telling a deliberately compatible server to break itself,
// which is the mistake the ping check already made once.
func TestDeclaredCompatibilityIsNotAFinding(t *testing.T) {
	s := runStateless(t, statelessFake(t, statelessOpts{
		serveRemoved:      true,
		supportedVersions: `["2026-07-28","2025-11-25","2025-06-18"]`,
	}), nil)
	f, ok := findingByID(s, "protocol.deprecated_features")
	if !ok {
		t.Fatal("protocol.deprecated_features is missing")
	}
	if f.Status != Pass {
		t.Fatalf("status = %s: %s", f.Status, f.Detail)
	}
	for _, want := range []string{"2025-06-18", "2025-11-25", "deliberately"} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("detail does not mention %q: %q", want, f.Detail)
		}
	}
	// The current revision is not a handshake revision and must not be
	// listed as evidence of compatibility with one.
	if strings.Contains(f.Detail, "2026-07-28, ") {
		t.Errorf("the stateless revision was counted as a handshake revision: %q", f.Detail)
	}
}

// The reverse is worse than silence: a client that reads supportedVersions
// will negotiate down to a revision this server does not serve, and the
// failure lands on the first real call.
func TestDeclaringVersionsItDoesNotServe(t *testing.T) {
	s := runStateless(t, statelessFake(t, statelessOpts{
		supportedVersions: `["2026-07-28","2025-11-25"]`,
	}), nil)
	f, ok := findingByID(s, "protocol.deprecated_features")
	if !ok {
		t.Fatal("protocol.deprecated_features is missing")
	}
	if f.Status != Warn {
		t.Fatalf("status = %s: %s", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, "2025-11-25") || !strings.Contains(f.Detail, "neither") {
		t.Errorf("detail does not describe the contradiction: %q", f.Detail)
	}
}

// Both checks are about a mechanism the handshake revisions do not have, so
// on those they are named and skipped. A report that simply contained two
// fewer checks would read as a better result.
func TestSpecFloorSkipsOnHandshakeRevision(t *testing.T) {
	f := newFakeServer(t)
	_, fs := run(t, f, ccCreds(), nil)
	for _, id := range []string{"protocol.extensions", "protocol.deprecated_features"} {
		got, ok := fs[id]
		if !ok {
			t.Errorf("%s is missing; it should be skipped, not absent", id)
			continue
		}
		if got.Status != Skip {
			t.Errorf("%s = %s: %s", id, got.Status, got.Detail)
		}
	}
}

// Enumeration separates the specification's own extensions from an author's,
// because "this server speaks Tasks" and "this server speaks something only
// its own client knows about" are different facts about the same list.
func TestExtensionsAreEnumerated(t *testing.T) {
	s := runStateless(t, statelessFake(t, statelessOpts{
		extensions: `["io.modelcontextprotocol/tasks","com.example.mcp/billing"]`,
	}), nil)
	f, ok := findingByID(s, "protocol.extensions")
	if !ok {
		t.Fatal("protocol.extensions is missing")
	}
	if f.Status != Pass {
		t.Fatalf("status = %s: %s", f.Status, f.Detail)
	}
	for _, want := range []string{
		"2 extensions advertised",
		"1 defined by the specification (io.modelcontextprotocol/tasks)",
		"1 third-party (com.example.mcp/billing)",
	} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("detail does not contain %q: %q", want, f.Detail)
		}
	}
	ev := strings.Join(f.Evidence, " ")
	for _, want := range []string{"io.modelcontextprotocol/tasks", "com.example.mcp/billing"} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence does not carry %q: %v", want, f.Evidence)
		}
	}
}

// A server with no extensions is not a defect, and must not read as one.
func TestNoExtensionsIsInformational(t *testing.T) {
	s := runStateless(t, statelessFake(t, statelessOpts{}), nil)
	f, ok := findingByID(s, "protocol.extensions")
	if !ok {
		t.Fatal("protocol.extensions is missing")
	}
	if f.Status != Info {
		t.Errorf("status = %s: %s", f.Status, f.Detail)
	}
}

func TestExtensionIdentifierShape(t *testing.T) {
	// A bare word claims no namespace, so the next server to pick it means
	// something else and a client cannot tell the two apart.
	t.Run("not reverse-DNS", func(t *testing.T) {
		s := runStateless(t, statelessFake(t, statelessOpts{
			extensions: `["billing","com.example.mcp/ok"]`,
		}), nil)
		f, ok := findingByID(s, "protocol.extensions")
		if !ok {
			t.Fatal("protocol.extensions is missing")
		}
		if f.Status != Warn {
			t.Fatalf("status = %s: %s", f.Status, f.Detail)
		}
		if !strings.Contains(f.Detail, "billing") || !strings.Contains(f.Detail, "reverse-DNS") {
			t.Errorf("detail = %q", f.Detail)
		}
		// The valid one is still evidence: across a population the useful
		// question is which extensions exist, and one bad identifier does
		// not make the rest of the list unreadable.
		if !strings.Contains(strings.Join(f.Evidence, " "), "com.example.mcp/ok") {
			t.Errorf("the valid identifier was dropped from the evidence: %v", f.Evidence)
		}
	})

	// Advertised where no client looks: a top-level list is not
	// capabilities.extensions, so a client following the specification
	// sees a server with none. An earlier version of this check read the
	// top-level list and so reported correct servers as having nothing.
	t.Run("not an object", func(t *testing.T) {
		s := runStateless(t, statelessFake(t, statelessOpts{
			rawCapabilities: `{"tools":{},"extensions":["io.modelcontextprotocol/tasks"]}`,
		}), nil)
		f, ok := findingByID(s, "protocol.extensions")
		if !ok {
			t.Fatal("protocol.extensions is missing")
		}
		if f.Status != Warn || !strings.Contains(f.Detail, "not an object") {
			t.Fatalf("got %s: %s", f.Status, f.Detail)
		}
	})

	t.Run("misplaced", func(t *testing.T) {
		s := runStateless(t, statelessFake(t, statelessOpts{
			legacyExtensions: `["io.modelcontextprotocol/tasks"]`,
		}), nil)
		f, ok := findingByID(s, "protocol.extensions")
		if !ok {
			t.Fatal("protocol.extensions is missing")
		}
		if f.Status != Warn || !strings.Contains(f.Detail, "capabilities.extensions") {
			t.Fatalf("got %s: %s", f.Status, f.Detail)
		}
	})
}

// The identifier rule in isolation, because the run-level tests can only
// reach a handful of shapes and the regexp is the thing being trusted.
func TestExtensionIDRule(t *testing.T) {
	ok := []string{
		"io.modelcontextprotocol/tasks",
		"com.example.mcp/billing",
		"com.example",
		"co.uk.acme-labs/thing.v2",
		"com.example/a/b",
	}
	bad := []string{
		"",
		"billing",
		"Com.Example/Billing",
		"com.example /billing",
		".com.example",
		"com.example./billing",
		"com..example/billing",
		"com.example/bill ing",
	}
	for _, id := range ok {
		if !extensionID.MatchString(id) {
			t.Errorf("%q was rejected and should not be", id)
		}
	}
	for _, id := range bad {
		if extensionID.MatchString(id) {
			t.Errorf("%q was accepted and should not be", id)
		}
	}
}

// replied decides whether a removed method is still served, and the whole
// check hangs off it. Two of its conditions are not reachable from the fake:
// a refusal carrying a JSON-RPC error is, but a refusal carrying a result at
// a non-2xx status is not — a server would have to be strange to do it, and
// a proxy in front of one is not strange at all. So the predicate is tested
// directly rather than left to the one path a fixture happens to take.
func TestRepliedPredicate(t *testing.T) {
	result := &transport.Response{JSONRPC: "2.0"}
	refusal := &transport.Response{JSONRPC: "2.0", Error: &transport.RPCError{Code: -32601}}

	cases := []struct {
		name string
		rep  rawReply
		want bool
	}{
		{"no reply at all", rawReply{}, false},
		{"JSON-RPC refusal over HTTP", rawReply{Response: refusal, Status: 404, HTTP: true}, false},
		{"JSON-RPC refusal at 200", rawReply{Response: refusal, Status: 200, HTTP: true}, false},
		{"result at 200", rawReply{Response: result, Status: 200, HTTP: true}, true},
		// The one the fixture cannot reach: a body that parses as a result
		// behind a status that says the request did not succeed. Reading it
		// as "still served" would report a gateway's error page as a
		// surviving handler.
		{"result at 502", rawReply{Response: result, Status: 502, HTTP: true}, false},
		{"result at 405", rawReply{Response: result, Status: 405, HTTP: true}, false},
		// Over a pipe there is no status, so the reply is the whole signal.
		{"result over a pipe", rawReply{Response: result}, true},
		{"refusal over a pipe", rawReply{Response: refusal}, false},
	}
	for _, c := range cases {
		if got := replied(c.rep); got != c.want {
			t.Errorf("%s: replied = %v, want %v", c.name, got, c.want)
		}
	}
}
