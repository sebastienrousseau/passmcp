// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package discover

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp/internal/report"
	"satellion.com/passmcp/internal/telemetry"
)

// AC: DISC-01
func TestTargetsFileNamesSingleHostsOnly(t *testing.T) {
	in := `# the hosts we run
notes.example
crm.example:8443   # a port
https://docs.example/mcp

http://intranet.example/sse
`
	got, err := ParseTargets(strings.NewReader(in), "targets.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://notes.example", "https://crm.example:8443", "https://docs.example/mcp", "http://intranet.example/sse"}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i, tgt := range got {
		if tgt.URL != want[i] || tgt.Source != (Source{Type: SourceTargets, Ref: "targets.txt"}) {
			t.Errorf("line %d: %+v, want %s", i, tgt, want[i])
		}
	}
	// A range or wildcard is a scan; so is anything that is not http(s).
	for _, bad := range []string{"10.0.0.0/24", "2001:db8::/32", "*.example", "ftp://files.example", "https://"} {
		if _, err := ParseTargets(strings.NewReader(bad), "t"); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestTwoTargetsReachingOneEndpointMergeTheirSources(t *testing.T) {
	srv := (&fakeMCP{}).start(t)
	a := Target{URL: srv.url(), Source: Source{Type: SourceTargets, Ref: "a.txt"}}
	b := Target{URL: srv.url() + "/mcp", Source: Source{Type: SourceConfig, Ref: "cursor.json"}}
	dup := a
	res := Run(context.Background(), Options{Targets: []Target{a, b, dup}, Recorder: telemetry.New(), Concurrency: 1})
	if len(res.Endpoints) != 1 || len(res.Endpoints[0].Sources) != 2 {
		t.Fatalf("one endpoint named twice should carry both sources once: %+v", res.Endpoints)
	}
}

func TestStateFileErrors(t *testing.T) {
	dir := t.TempDir()
	if s, err := LoadState(filepath.Join(dir, "absent.json")); err != nil || len(s.Endpoints) != 0 {
		t.Fatalf("a missing state file is an empty state: %v", err)
	}
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte("{"), 0o600)
	if _, err := LoadState(bad); err == nil {
		t.Error("a malformed state file was accepted")
	}
	old := filepath.Join(dir, "old.json")
	_ = os.WriteFile(old, []byte(`{"version": 9}`), 0o600)
	if _, err := LoadState(old); err == nil {
		t.Error("a state file of another format version was accepted")
	}
	empty := filepath.Join(dir, "empty.json")
	_ = os.WriteFile(empty, []byte(`{"version": 1}`), 0o600)
	if s, err := LoadState(empty); err != nil || s.Endpoints == nil {
		t.Errorf("a state file with no endpoints: %v", err)
	}
	if err := (&State{Version: 1}).Save(filepath.Join(dir, "missing", "s.json")); err == nil {
		t.Error("saving into a directory that does not exist succeeded")
	}
	if _, err := LoadState(dir); err == nil {
		t.Error("a directory was read as a state file")
	}
}

func TestJSONCCommentsAndStringsSurvive(t *testing.T) {
	in := []byte(`{
	  /* block */ "a": "keep // this and /* that */",
	  "b": "escaped \" quote", // line
	  "c": [1, 2,],
	  /* unterminated`)
	out := string(stripJSONC(in))
	for _, want := range []string{`"keep // this and /* that */"`, `"escaped \" quote"`, `[1, 2]`} {
		if !strings.Contains(out, want) {
			t.Errorf("stripped output lost %s:\n%s", want, out)
		}
	}
	if strings.Contains(out, "block") || strings.Contains(out, "line") || strings.Contains(out, "unterminated") {
		t.Errorf("a comment survived:\n%s", out)
	}
	if _, err := FromClientConfig([]byte("not json"), "x"); err == nil {
		t.Error("a non-JSON client configuration was accepted")
	}
}

func TestSourcesSkipWhatIsNotARemoteServer(t *testing.T) {
	got, err := FromClientConfig([]byte(`{"mcpServers": {"x": "not an object", "y": {"serverUrl": "https://y.example/mcp"}}, "servers": []}`), "c.json")
	if err != nil || len(got) != 1 || got[0].URL != "https://y.example/mcp" {
		t.Fatalf("got %+v %v", got, err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	_ = os.WriteFile(p, []byte("x"), 0o600)
	if b, err := ReadFile(p); err != nil || string(b) != "x" {
		t.Errorf("ReadFile: %q %v", b, err)
	}
}

func TestRegistryErrorsAreReported(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer down.Close()
	if _, err := FromRegistry(context.Background(), down.Client(), down.URL, "io.github.acme"); err == nil {
		t.Error("a registry answering 503 gave no error")
	}
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{"))
	}))
	defer garbage.Close()
	if _, err := FromRegistry(context.Background(), garbage.Client(), garbage.URL, "io.github.acme"); err == nil {
		t.Error("a malformed registry response gave no error")
	}
	if _, err := FromRegistry(context.Background(), http.DefaultClient, "http://[::1", "io.github.acme"); err == nil {
		t.Error("an invalid registry URL gave no error")
	}
}

func TestTextOutputCoversEveryCase(t *testing.T) {
	res := &Result{
		Targets: []Target{target("https://a.example")},
		Endpoints: []Endpoint{
			{URL: "https://a.example/mcp", Method: "initialize", Proof: 1, Status: StatusNew},
			{URL: "https://b.example/mcp", Method: "initialize", Proof: 2, Server: "b", Status: StatusSeen,
				Attestation: &Validation{Error: "timeout"}},
			{URL: "https://c.example/mcp", Method: "initialize", Proof: 3, Server: "c", Version: "1", Status: StatusSeen,
				Attestation: &Validation{File: "c.json", Score: 90, Grade: "A"}},
		},
		Disappeared: []Endpoint{{URL: "https://d.example/mcp", LastSeen: time.Unix(0, 0).UTC()}},
		Protected:   []Protected{{URL: "https://e.example/mcp", Proof: 4}},
		Blocked:     []string{"evil.example:443"},
	}
	var b bytes.Buffer
	WriteText(&b, res)
	for _, want := range []string{"an unnamed server", "check failed: timeout", "grade A", "[disappeared]", "answered 401", "not contacted", "evil.example:443"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("text output lacks %q:\n%s", want, b.String())
		}
	}
}

func TestAuthOfFollowsTheEvidence(t *testing.T) {
	if got := authOf(&Endpoint{Exposed: true}, nil); got != "none" {
		t.Errorf("exposed: %s", got)
	}
	if got := authOf(&Endpoint{}, &report.Report{Auth: report.AuthSummary{Required: true}}); got != "oauth" {
		t.Errorf("required: %s", got)
	}
	if got := authOf(&Endpoint{}, &report.Report{}); got != "unknown" {
		t.Errorf("unknown: %s", got)
	}
}

// AC: DISC-02
func TestTheScopeRefusesBeforeSending(t *testing.T) {
	sc := newScope([]Target{target("https://named.example")})
	called := false
	tr := &scopedTransport{scope: sc, base: roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("unreachable")
	})}
	req, _ := http.NewRequest(http.MethodGet, "https://other.example/mcp", nil)
	if _, err := tr.RoundTrip(req); !errors.Is(err, ErrOutOfScope) || called {
		t.Fatalf("an out-of-scope request was sent (err %v, sent %v)", err, called)
	}
	// Default ports are the same host: https://named.example:443 is named.
	u, _ := url.Parse("https://named.example:443/x")
	if !sc.allows(u) {
		t.Error("the explicit default port was treated as another host")
	}
	// Redirects stop after three hops even inside the scope.
	var via []*http.Request
	for range 3 {
		via = append(via, req)
	}
	in, _ := http.NewRequest(http.MethodGet, "https://named.example/next", nil)
	if err := sc.checkRedirect(in, via); !errors.Is(err, http.ErrUseLastResponse) {
		t.Errorf("a fourth redirect was followed: %v", err)
	}
	if err := sc.checkRedirect(in, nil); err != nil {
		t.Errorf("an in-scope redirect was refused: %v", err)
	}
}

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSmallHelpers(t *testing.T) {
	if got := bound(strings.Repeat("x", 300)); len(got) > 204 || !strings.HasSuffix(got, "…") {
		t.Errorf("bound did not cap: %d", len(got))
	}
	if got := resourceMetadata(http.Header{"Www-Authenticate": {`Bearer realm="x", resource_metadata="https://a/.well-known/oauth-protected-resource"`}}); got != "https://a/.well-known/oauth-protected-resource" {
		t.Errorf("resource_metadata %q", got)
	}
	if got := resourceMetadata(http.Header{}); got != "" {
		t.Errorf("no challenge gave %q", got)
	}
	if !isURLKey("serverUrl") || isURLKey("name") {
		t.Error("isURLKey")
	}
	if h := sessionHeaders(http.Header{}, ""); h.protocol == "" {
		t.Error("a missing protocol version was not defaulted")
	}
	if _, ok := resultOf(&response{status: 500}); ok {
		t.Error("a 500 carried a result")
	}
	l := newLimiter(1)
	ctx, cancel := context.WithCancel(context.Background())
	_ = l.wait(ctx)
	cancel()
	if err := l.wait(ctx); err == nil {
		t.Error("a cancelled wait returned no error")
	}
}
