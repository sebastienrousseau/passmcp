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
	"testing"
	"time"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/telemetry"
	"satellion.com/passmcp/transport"
)

func intp(n int) *int { return &n }

// hintSession builds a session speaking the given era.
func hintSession(era passmcp.Era) *Session {
	return &Session{
		Opts: Options{Recorder: &telemetry.Recorder{}},
		Era:  &passmcp.Negotiation{Era: era},
	}
}

// TestCacheHintsSkipBeforeTheRevisionThatHasThem: these fields arrived in
// 2026-07-28 (SEP-2549). Reporting their absence on an older server would be
// a finding about the revision the operator runs, not about the server.
func TestCacheHintsSkipBeforeTheRevisionThatHasThem(t *testing.T) {
	out := checkCacheHints(hintSession(passmcp.EraSession), passmcp.CacheHints{}, 50000)
	if len(out) != 1 || out[0].Status != Skip {
		t.Fatalf("want a skip on a session-era server, got %+v", out)
	}
	if !strings.Contains(out[0].Detail, "2026-07-28") {
		t.Errorf("the skip does not name the revision: %q", out[0].Detail)
	}
}

// TestCacheHintsPassWhenBothAreStated, and says what they were.
func TestCacheHintsPassWhenBothAreStated(t *testing.T) {
	out := checkCacheHints(hintSession(passmcp.EraStateless),
		passmcp.CacheHints{TTLMs: intp(300000), Scope: "public"}, 50000)

	if len(out) != 1 || out[0].Status != Pass {
		t.Fatalf("want a pass, got %+v", out)
	}
	if !strings.Contains(out[0].Detail, "5m") {
		t.Errorf("the detail does not render the TTL: %q", out[0].Detail)
	}
	if !strings.Contains(out[0].Detail, "public") {
		t.Errorf("the detail does not carry the scope: %q", out[0].Detail)
	}
}

// TestCacheHintsWarnWhenIncomplete: SEP-2549 requires both ttlMs and
// cacheScope on 2026-07-28 list results.
func TestCacheHintsWarnWhenIncomplete(t *testing.T) {
	onlyTTL := checkCacheHints(hintSession(passmcp.EraStateless),
		passmcp.CacheHints{TTLMs: intp(60000)}, 100)
	if len(onlyTTL) != 1 || onlyTTL[0].Status != Warn || !strings.Contains(onlyTTL[0].Detail, "cacheScope") {
		t.Fatalf("ttlMs without cacheScope: got %+v, want warn naming cacheScope", onlyTTL)
	}

	onlyScope := checkCacheHints(hintSession(passmcp.EraStateless),
		passmcp.CacheHints{Scope: "public"}, 100)
	if len(onlyScope) != 1 || onlyScope[0].Status != Warn || !strings.Contains(onlyScope[0].Detail, "ttlMs") {
		t.Fatalf("cacheScope without ttlMs: got %+v, want warn naming ttlMs", onlyScope)
	}
}

// TestCacheHintsFailOnInvalidValues: negative ttlMs or an unknown cacheScope
// violates the SEP-2549 wire schema.
func TestCacheHintsFailOnInvalidValues(t *testing.T) {
	neg := checkCacheHints(hintSession(passmcp.EraStateless),
		passmcp.CacheHints{TTLMs: intp(-10), Scope: "public"}, 100)
	if len(neg) != 1 || neg[0].Status != Fail || !strings.Contains(neg[0].Detail, "negative ttlMs") {
		t.Fatalf("negative ttlMs: got %+v, want fail", neg)
	}

	badScope := checkCacheHints(hintSession(passmcp.EraStateless),
		passmcp.CacheHints{TTLMs: intp(0), Scope: "shared"}, 100)
	if len(badScope) != 1 || badScope[0].Status != Fail || !strings.Contains(badScope[0].Detail, "cacheScope") {
		t.Fatalf("invalid cacheScope: got %+v, want fail", badScope)
	}
}

// TestCacheHintsWarnWhenMissingOnStateless: SEP-2549 makes both fields
// required on 2026-07-28 list results, noting token cost on large catalogues.
func TestCacheHintsWarnWhenMissingOnStateless(t *testing.T) {
	large := checkCacheHints(hintSession(passmcp.EraStateless), passmcp.CacheHints{}, cacheHintFloor+1)
	if len(large) != 1 || large[0].Status != Warn || !strings.Contains(large[0].Detail, "tokens") {
		t.Fatalf("large silent catalogue: got %+v, want warn with token count", large)
	}

	small := checkCacheHints(hintSession(passmcp.EraStateless), passmcp.CacheHints{}, 100)
	if len(small) != 1 || small[0].Status != Warn || !strings.Contains(small[0].Advice, "ttlMs") {
		t.Fatalf("small silent 2026-07-28 catalogue: got %+v, want warn naming ttlMs", small)
	}
}

// TestCacheHintsSkipWithNoNegotiation: without knowing the era there is
// nothing to say, and guessing would produce a finding about passmcp.
func TestCacheHintsSkipWithNoNegotiation(t *testing.T) {
	s := &Session{Opts: Options{Recorder: &telemetry.Recorder{}}}
	out := checkCacheHints(s, passmcp.CacheHints{}, 50000)
	if len(out) != 1 || out[0].Status != Skip {
		t.Fatalf("want a skip when the era is unknown, got %+v", out)
	}
}

// TestCacheHintsStated covers the helper the check branches on.
func TestCacheHintsStated(t *testing.T) {
	if (passmcp.CacheHints{}).Stated() {
		t.Error("an empty hint should not count as stated")
	}
	if !(passmcp.CacheHints{TTLMs: intp(0)}).Stated() {
		t.Error("ttlMs of zero is still a statement: cache this for no time at all")
	}
	if !(passmcp.CacheHints{Scope: "private"}).Stated() {
		t.Error("a scope alone is a statement")
	}
}

// TestCacheHintsCoversResourcesAndPromptsWithoutPenalizingUndeclaredEndpoints
// verifies that a resources-only 2026-07-28 server gets catalog.cache_hints
// judged on resources/list while undeclared tools/list and prompts/list do
// not count against it.
func TestCacheHintsCoversResourcesAndPromptsWithoutPenalizingUndeclaredEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		if h := r.Header.Get(transport.HeaderMethod); h != "" && h != req.Method {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":"mismatch"}}`, req.ID, transport.CodeHeaderMismatch)
			return
		}
		switch req.Method {
		case "server/discover":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","serverInfo":{"name":"res-cache","version":"1.0"},"capabilities":{"resources":{},"prompts":{}}}}`, req.ID)
		case "resources/list":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","resources":[{"uri":"fake://1","name":"one","mimeType":"text/plain"}],"ttlMs":120000,"cacheScope":"public"}}`, req.ID)
		case "resources/templates/list":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","resourceTemplates":[],"ttlMs":120000,"cacheScope":"public"}}`, req.ID)
		case "prompts/list":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","prompts":[{"name":"p1","description":"Describe a document clearly"}],"ttlMs":0,"cacheScope":"private"}}`, req.ID)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"not implemented"}}`, req.ID)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s, err := Run(ctx, Options{
		Endpoint: srv.URL, HTTPClient: srv.Client(), Version: "test",
		Creds: &creds.Credentials{Mode: creds.ModeNone},
		Only:  []string{"discovery", "handshake", "catalog"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	f, ok := findingByID(s, "catalog.cache_hints")
	if !ok {
		t.Fatal("missing catalog.cache_hints on resources+prompts server")
	}
	if f.Status != Pass {
		t.Errorf("catalog.cache_hints = %s (%q), want pass", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, "resources/list") || !strings.Contains(f.Detail, "prompts/list") {
		t.Errorf("detail should name both listed endpoints: %q", f.Detail)
	}
}
