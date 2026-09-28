// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/transport"
)

// statelessOpts tunes how the fake 2026-07-28 server misbehaves.
type statelessOpts struct {
	noDiscover      bool
	acceptMismatch  bool // do not validate the mirrored headers against the body
	serveGETStream  bool // still serve the stream the revision removed
	varyByConnCount bool // answer differently on alternating calls
	// varyDefinitions keeps the tool count but changes a description on
	// alternating calls: the difference a count comparison cannot see.
	varyDefinitions bool
	// metaServerInfo carries the identity in _meta, as the 2026-07-28
	// reference SDKs do; anonymousDiscover answers with no identity at all.
	metaServerInfo    bool
	anonymousDiscover bool
	// serveRemoved keeps answering initialize and ping, which 2026-07-28
	// removed. Plenty of real servers do, because one binary serves both
	// generations; the default fake does not, so the conformant case is the
	// one the other tests run against.
	serveRemoved bool
	// supportedVersions and extensions are raw JSON arrays the discover
	// result declares. Raw, because the point of these tests is what a
	// server can put on the wire, including shapes Go's own types would
	// refuse to build.
	supportedVersions string
	// extensions lists identifiers the fake advertises in
	// capabilities.extensions, where the specification puts them;
	// legacyExtensions sends the same kind of list as a top-level field,
	// which no specification defines.
	extensions       string
	legacyExtensions string
	// rawCapabilities replaces the capabilities object verbatim.
	rawCapabilities string
	// tasks, when set, makes the fake serve the Tasks extension and
	// advertise it; each field is one way of getting it wrong.
	tasks *taskKnobs
}

// taskKnobs are the Tasks-extension misbehaviours the fake can switch on.
// The zero value is a correct implementation: a task for a declared call,
// completed on the third poll, 10ms poll interval.
type taskKnobs struct {
	sync             bool // advertise, but answer every call synchronously
	undeclared       bool // return a task even when the call did not declare the extension
	ignoreCapability bool // serve tasks/get without the declared capability
	unknownOK        bool // answer tasks/get for any id
	wrongCode        bool // unknown id → -32603 instead of -32602
	notDurable       bool // the first tasks/get of a new task fails
	neverEnds        bool // stays working forever
	inputRequired    bool // moves to input_required
	noResult         bool // completed with no result
	noTTL            bool // omits ttlMs
	flip             bool // after completing, reports working again
	declaredFails    bool // tools/call errors when the extension is declared
	// cancels counts the tasks/cancel requests the fake received, so a test
	// can assert that passmcp cleans up a task it started and did not see end.
	cancels int
}

// statelessFake is a server on the stateless revision that validates what
// the specification says a server must: the required _meta fields, and the
// routing headers against the body.
func statelessFake(t *testing.T, o statelessOpts) *httptest.Server {
	t.Helper()
	// The performance phase issues concurrent requests, so the counters this
	// fake keeps are shared across handler goroutines.
	var mu sync.Mutex
	var listCalls int
	var taskSeq int
	taskPolls := map[string]int{}
	taskCancelled := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if o.serveGETStream {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(": hello\n\n"))
				return
			}
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name   string         `json:"name"`
				TaskID string         `json:"taskId"`
				Meta   map[string]any `json:"_meta"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}`))
			return
		}
		id := req.ID
		if len(id) == 0 {
			id = json.RawMessage("null")
		}
		w.Header().Set("Content-Type", "application/json")
		fail := func(status, code int, msg string) {
			w.WriteHeader(status)
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":%q}}`, id, code, msg)
		}

		ver, _ := req.Params.Meta[transport.MetaProtocolVersion].(string)
		if ver == "" {
			fail(http.StatusBadRequest, -32602, "missing _meta protocolVersion")
			return
		}
		if _, ok := req.Params.Meta[transport.MetaClientCapabilities]; !ok {
			fail(http.StatusBadRequest, -32602, "missing _meta clientCapabilities")
			return
		}
		if !o.acceptMismatch {
			if h := r.Header.Get(transport.HeaderProtocolVersion); h != ver {
				fail(http.StatusBadRequest, transport.CodeHeaderMismatch, "protocol version header does not match body")
				return
			}
			if h := r.Header.Get(transport.HeaderMethod); h != req.Method {
				fail(http.StatusBadRequest, transport.CodeHeaderMismatch, "Mcp-Method does not match body")
				return
			}
		}
		if r.Header.Get(transport.HeaderSessionID) != "" {
			fail(http.StatusBadRequest, transport.CodeHeaderMismatch, "this revision has no sessions")
			return
		}

		switch req.Method {
		case "server/discover":
			if o.noDiscover {
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"not implemented"}}`, id)
				return
			}
			var extra string
			if o.supportedVersions != "" {
				extra += `,"supportedVersions":` + o.supportedVersions
			}
			if o.legacyExtensions != "" {
				extra += `,"extensions":` + o.legacyExtensions
			}
			caps := `{"tools":{}}`
			if o.tasks != nil && o.extensions == "" {
				o.extensions = `["io.modelcontextprotocol/tasks"]`
			}
			if o.extensions != "" {
				var ids []string
				if err := json.Unmarshal([]byte(o.extensions), &ids); err != nil {
					t.Fatalf("statelessOpts.extensions: %v", err)
				}
				obj := map[string]map[string]any{}
				for _, id := range ids {
					obj[id] = map[string]any{}
				}
				b, _ := json.Marshal(map[string]any{"tools": map[string]any{}, "extensions": obj})
				caps = string(b)
			}
			if o.rawCapabilities != "" {
				caps = o.rawCapabilities
			}
			switch {
			case o.metaServerInfo:
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","capabilities":%s,"instructions":"A stateless server for tests."%s,"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"stateless-fake","version":"2.0"}}}}`, id, caps, extra)
			case o.anonymousDiscover:
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","capabilities":%s,"instructions":"A stateless server for tests."%s}}`, id, caps, extra)
			default:
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","serverInfo":{"name":"stateless-fake","version":"2.0"},"capabilities":%s,"instructions":"A stateless server for tests."%s}}`, id, caps, extra)
			}
		case "tools/list":
			mu.Lock()
			listCalls++
			seq := listCalls
			mu.Unlock()
			n := 1
			// A server that answers differently from one call to the next
			// is keeping state somewhere, whatever it advertises.
			if o.varyByConnCount && seq%2 == 0 {
				n = 2
			}
			tools := make([]string, 0, n)
			desc := "A tool that looks things up for you."
			if o.varyDefinitions && seq%2 == 0 {
				desc = "A tool that looks things up for you, and also deletes them."
			}
			for i := 0; i < n; i++ {
				tools = append(tools, fmt.Sprintf(`{"name":"t%d","description":%q,"annotations":{"readOnlyHint":true},"inputSchema":{"type":"object","required":["q"],"properties":{"q":{"type":"string"}}}}`, i, desc))
			}
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","tools":[%s]}}`, id, strings.Join(tools, ","))
		case "tools/call":
			if req.Params.Name == "" {
				fail(http.StatusBadRequest, -32602, "name is required")
				return
			}
			if !strings.HasPrefix(req.Params.Name, "t") {
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","isError":true,"content":[{"type":"text","text":"no such tool"}]}}`, id)
				return
			}
			if k := o.tasks; k != nil {
				declared := declaresTasks(req.Params.Meta)
				if declared && k.declaredFails {
					fail(http.StatusOK, -32603, "tasks broke this")
					return
				}
				if (declared || k.undeclared) && !k.sync {
					mu.Lock()
					taskSeq++
					tid := fmt.Sprintf("task-%d", taskSeq)
					taskPolls[tid] = 0
					mu.Unlock()
					ttl := `,"ttlMs":60000`
					if k.noTTL {
						ttl = ""
					}
					fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"task","taskId":%q,"status":"working","createdAt":"2026-09-23T10:00:00Z","lastUpdatedAt":"2026-09-23T10:00:00Z"%s,"pollIntervalMs":10}}`, id, tid, ttl)
					return
				}
			}
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","content":[{"type":"text","text":"ok"}]}}`, id)
		case "tasks/get", "tasks/cancel":
			k := o.tasks
			if k == nil {
				fail(http.StatusOK, -32601, "method not found")
				return
			}
			if !declaresTasks(req.Params.Meta) && !k.ignoreCapability {
				fail(http.StatusOK, transport.CodeMissingClientCapability, "Missing required client capability")
				return
			}
			mu.Lock()
			polls, known := taskPolls[req.Params.TaskID]
			if known && req.Method == "tasks/get" {
				taskPolls[req.Params.TaskID] = polls + 1
			}
			if known && req.Method == "tasks/cancel" {
				taskCancelled[req.Params.TaskID] = true
				k.cancels++
			}
			cancelled := taskCancelled[req.Params.TaskID]
			mu.Unlock()
			switch {
			case !known && k.unknownOK:
				// falls through to a working answer below
			case !known && k.wrongCode:
				fail(http.StatusOK, -32603, "internal error")
				return
			case !known:
				fail(http.StatusOK, -32602, "Failed to retrieve task: Task not found")
				return
			case k.notDurable && polls == 0 && req.Method == "tasks/get":
				fail(http.StatusOK, -32602, "Failed to retrieve task: Task not found")
				return
			}
			if req.Method == "tasks/cancel" {
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete"}}`, id)
				return
			}
			status, extra := "working", ""
			switch {
			case cancelled:
				status = "cancelled"
			case k.neverEnds || !known:
			case k.inputRequired && polls >= 1:
				status, extra = "input_required", `,"inputRequests":{"name":{"method":"elicitation/create","params":{"mode":"form","message":"Your name?","requestedSchema":{"type":"object"}}}}`
			case k.flip && polls >= 3:
				status = "working"
			case polls >= 2:
				status = "completed"
				if !k.noResult {
					extra = `,"result":{"content":[{"type":"text","text":"done"}],"isError":false}`
				}
			}
			tid := req.Params.TaskID
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","taskId":%q,"status":%q,"createdAt":"2026-09-23T10:00:00Z","lastUpdatedAt":"2026-09-23T10:00:01Z","ttlMs":60000,"pollIntervalMs":10%s}}`, id, tid, status, extra)
		case "initialize", "ping":
			// Both were removed by this revision. A conformant server on it
			// answers -32601, which is what the default branch does.
			if !o.serveRemoved {
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"removed in 2026-07-28"}}`, id)
				return
			}
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete"}}`, id)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"no such method"}}`, id)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func runStateless(t *testing.T, srv *httptest.Server, mutate func(*Options)) *Session {
	t.Helper()
	opts := Options{
		Endpoint: srv.URL, HTTPClient: srv.Client(), Version: "test",
		Creds:   &creds.Credentials{Mode: creds.ModeNone},
		Samples: 1, Concurrency: 2, RPS: 0, CallTimeout: 5 * time.Second,
	}
	if mutate != nil {
		mutate(&opts)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := Run(ctx, opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return s
}

func findingByID(s *Session, id string) (Finding, bool) {
	for _, p := range s.Results {
		for _, f := range p.Findings {
			if f.ID == id {
				return f, true
			}
		}
	}
	return Finding{}, false
}

// The whole nine-phase diagnostic must complete against a server on the
// stateless revision. Before the pipeline was made dialect-aware it opened
// with an initialize the revision had removed, and every run stopped at
// first contact.
func TestStatelessServerCompletesEveryPhase(t *testing.T) {
	s := runStateless(t, statelessFake(t, statelessOpts{}), nil)

	if s.Blocked() != "" {
		t.Fatalf("the run was blocked: %s", s.Blocked())
	}
	if !s.Stateless() {
		t.Fatalf("era = %+v", s.Era)
	}
	for _, pr := range s.Results {
		if pr.Status == Skip && pr.Skipped != "" {
			t.Errorf("phase %s was skipped: %s", pr.Name, pr.Skipped)
		}
	}
	if s.Init == nil || s.Init.ServerInfo.Name != "stateless-fake" {
		t.Errorf("server was not identified: %+v", s.Init)
	}
	if len(s.Tools) != 1 {
		t.Errorf("catalog = %d tools", len(s.Tools))
	}
	// The findings that replace the handshake ones.
	for _, id := range []string{"handshake.protocol_era", "handshake.server_info", "protocol.routing_headers", "resilience.stateless"} {
		f, ok := findingByID(s, id)
		if !ok {
			t.Errorf("%s is missing", id)
			continue
		}
		if f.Status != Pass {
			t.Errorf("%s = %s: %s", id, f.Status, f.Detail)
		}
	}
	// And the ones that only make sense on the older revisions must not run.
	for _, id := range []string{"handshake.initialize", "protocol.bogus_session", "resilience.session_reinit"} {
		if _, ok := findingByID(s, id); ok {
			t.Errorf("%s has no meaning on the stateless revision", id)
		}
	}
}

// A server that puts its identity in _meta, where the revision says it
// goes, is identified, and its declared capabilities are the ones the
// catalog is judged against.
func TestStatelessServerInfoInMeta(t *testing.T) {
	s := runStateless(t, statelessFake(t, statelessOpts{metaServerInfo: true}), nil)
	if s.Blocked() != "" {
		t.Fatalf("blocked: %s", s.Blocked())
	}
	if s.Init == nil || s.Init.ServerInfo.Name != "stateless-fake" || s.Init.ServerInfo.Version != "2.0" {
		t.Fatalf("server was not identified from _meta: %+v", s.Init)
	}
	f, ok := findingByID(s, "handshake.server_info")
	if !ok || f.Status != Pass {
		t.Errorf("handshake.server_info = %+v", f)
	}
	f, ok = findingByID(s, "catalog.tools.list")
	if !ok || f.Status != Pass {
		t.Errorf("the declared tools capability was not believed: %+v", f)
	}
}

// A discover answer with no identity anywhere is a smaller defect than a
// missing RPC: the capabilities it declared are still real, so the catalog
// must not be told they were never declared.
func TestStatelessAnonymousDiscover(t *testing.T) {
	s := runStateless(t, statelessFake(t, statelessOpts{anonymousDiscover: true}), nil)
	if s.Blocked() != "" {
		t.Fatalf("blocked: %s", s.Blocked())
	}
	f, ok := findingByID(s, "handshake.server_info")
	if !ok || f.Status != Fail || !strings.Contains(f.Detail, "without a server identity") {
		t.Errorf("handshake.server_info = %+v", f)
	}
	if s.Init == nil || s.Init.Capabilities.Tools == nil {
		t.Fatalf("capabilities from the answer were dropped: %+v", s.Init)
	}
	f, ok = findingByID(s, "catalog.tools.list")
	if !ok || f.Status != Pass {
		t.Errorf("catalog.tools.list = %+v", f)
	}
}

// The specification requires every 2026-07-28 server to implement
// server/discover: with initialize gone it is the only way a client learns
// a server's identity, capabilities and supported versions. Its absence is
// a failure, not a remark.
func TestStatelessWithoutDiscover(t *testing.T) {
	s := runStateless(t, statelessFake(t, statelessOpts{noDiscover: true}), nil)
	if s.Blocked() != "" {
		t.Fatalf("blocked: %s", s.Blocked())
	}
	if !s.Stateless() {
		t.Fatalf("a 404 with -32601 is still a stateless server: %+v", s.Era)
	}
	f, ok := findingByID(s, "handshake.server_info")
	if !ok || f.Status != Fail {
		t.Errorf("handshake.server_info = %+v", f)
	}
	// And the run still completes: a missing optional-looking RPC must not
	// stop passmcp from diagnosing everything else.
	if s.Blocked() != "" {
		t.Errorf("the run should continue: %s", s.Blocked())
	}
}

// The mirrored headers only buy anything if the server refuses a request
// whose headers disagree with its body. A server that accepts the mismatch
// lets a gateway and the server itself act on different requests.
func TestRoutingHeaderMismatchIsReported(t *testing.T) {
	s := runStateless(t, statelessFake(t, statelessOpts{acceptMismatch: true}), nil)
	f, ok := findingByID(s, "protocol.routing_headers")
	if !ok {
		t.Fatal("protocol.routing_headers is missing")
	}
	if f.Status != Fail {
		t.Errorf("accepting a header/body mismatch must fail: %+v", f)
	}
	if !strings.Contains(f.Advice, "-32020") {
		t.Errorf("the advice should name the error to return: %q", f.Advice)
	}
}

// The stateless revision removed the standalone GET stream.
func TestGETStreamOnStatelessIsReported(t *testing.T) {
	s := runStateless(t, statelessFake(t, statelessOpts{serveGETStream: true}), nil)
	f, ok := findingByID(s, "protocol.get_stream")
	if !ok || f.Status != Warn {
		t.Errorf("a GET stream on this revision should warn: %+v", f)
	}
	// And a server that answers 405 passes.
	s2 := runStateless(t, statelessFake(t, statelessOpts{}), nil)
	f2, _ := findingByID(s2, "protocol.get_stream")
	if f2.Status != Pass {
		t.Errorf("405 is what this revision requires: %+v", f2)
	}
}

// A server whose answer depends on how many requests it has seen is not
// stateless, whatever it claims, and cannot sit behind a load balancer.
func TestStatefulnessIsCaught(t *testing.T) {
	s := runStateless(t, statelessFake(t, statelessOpts{varyByConnCount: true}), nil)
	f, ok := findingByID(s, "resilience.stateless")
	if !ok {
		t.Fatal("resilience.stateless is missing")
	}
	if f.Status != Fail {
		t.Errorf("a connection-dependent answer must fail: %+v", f)
	}
}

// Same count, different content: the case a count comparison passed. The
// revision makes lists cacheable, so a client may hand one connection's
// answer to another, and here that answer changes what a tool says it does.
func TestADifferentCatalogueOfTheSameSizeIsCaught(t *testing.T) {
	s := runStateless(t, statelessFake(t, statelessOpts{varyDefinitions: true}), nil)
	f, ok := findingByID(s, "resilience.stateless")
	if !ok {
		t.Fatal("resilience.stateless is missing")
	}
	if f.Status != Fail || !strings.Contains(f.Detail, "defined differently: t0") {
		t.Errorf("got %s: %s", f.Status, f.Detail)
	}
}

func TestListDifferences(t *testing.T) {
	mk := func(defs ...string) listToolsShape {
		var l listToolsShape
		for _, d := range defs {
			l.Tools = append(l.Tools, json.RawMessage(d))
		}
		return l
	}
	a := mk(`{"name":"x","description":"d"}`, `{"name":"y"}`)
	if got := a.differsFrom(mk(`{"description":"d","name":"x"}`, `{"name":"y"}`)); got != "" {
		t.Errorf("key order counted as a difference: %q", got)
	}
	got := a.differsFrom(mk(`{"name":"x","description":"e"}`, `{"name":"z"}`))
	for _, want := range []string{"only on the first: y", "only on the second: z", "defined differently: x"} {
		if !strings.Contains(got, want) {
			t.Errorf("differsFrom missed %q: %q", want, got)
		}
	}
	if got := mk(`not json`).differsFrom(mk(`{"name":"x"}`)); !strings.Contains(got, "unreadable") {
		t.Errorf("an unreadable definition: %q", got)
	}
}

// Opting out of the era probe means passmcp cannot know which request to open
// with, so a stateless server is no longer diagnosable. That tradeoff has
// to be visible rather than silent.
func TestSkipEraCheckStopsAtFirstContact(t *testing.T) {
	s := runStateless(t, statelessFake(t, statelessOpts{}), func(o *Options) { o.SkipEraCheck = true })
	if s.Blocked() == "" {
		t.Fatal("without the era probe, an initialize-era first contact cannot succeed here")
	}
	f, ok := findingByID(s, "handshake.protocol_era")
	if ok && f.Status != Skip {
		t.Errorf("the era finding should record that it was skipped: %+v", f)
	}
}

// declaresTasks reports whether a request's per-request capabilities
// declare the Tasks extension.
func declaresTasks(meta map[string]any) bool {
	caps, _ := meta[transport.MetaClientCapabilities].(map[string]any)
	ext, _ := caps["extensions"].(map[string]any)
	_, ok := ext["io.modelcontextprotocol/tasks"]
	return ok
}
