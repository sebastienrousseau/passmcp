// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"strings"
	"testing"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/telemetry"
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
// 2026-07-28. Reporting their absence on an older server would be a
// finding about the revision the operator runs, not about the server.
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

// TestCacheHintsPassWithTTLAlone, and says what the client must assume.
func TestCacheHintsPassWithTTLAlone(t *testing.T) {
	out := checkCacheHints(hintSession(passmcp.EraStateless),
		passmcp.CacheHints{TTLMs: intp(60000)}, 50000)

	if len(out) != 1 || out[0].Status != Pass {
		t.Fatalf("want a pass, got %+v", out)
	}
	if !strings.Contains(out[0].Detail, "private") {
		t.Errorf("the detail does not say what an absent scope means: %q", out[0].Detail)
	}
}

// TestCacheHintsPassWithScopeAlone: a scope with no lifetime says how the
// answer may be shared and not for how long, which is worth naming.
func TestCacheHintsPassWithScopeAlone(t *testing.T) {
	out := checkCacheHints(hintSession(passmcp.EraStateless),
		passmcp.CacheHints{Scope: "public"}, 50000)

	if len(out) != 1 || out[0].Status != Pass {
		t.Fatalf("want a pass, got %+v", out)
	}
	if !strings.Contains(out[0].Detail, "for how long") {
		t.Errorf("the detail does not say what is missing: %q", out[0].Detail)
	}
}

// TestCacheHintsWarnOnALargeSilentCatalogue is where it costs: every
// client re-fetches this on every session.
func TestCacheHintsWarnOnALargeSilentCatalogue(t *testing.T) {
	out := checkCacheHints(hintSession(passmcp.EraStateless), passmcp.CacheHints{}, cacheHintFloor+1)

	if len(out) != 1 || out[0].Status != Warn {
		t.Fatalf("want a warning on a large silent catalogue, got %+v", out)
	}
	if !strings.Contains(out[0].Advice, "ttlMs") {
		t.Errorf("the advice does not name the field to set: %q", out[0].Advice)
	}
}

// TestCacheHintsAreQuietOnASmallCatalogue: both fields are optional, and a
// catalogue nobody pays much to re-fetch is not a defect. A check that
// warned here would be one people filter out.
func TestCacheHintsAreQuietOnASmallCatalogue(t *testing.T) {
	out := checkCacheHints(hintSession(passmcp.EraStateless), passmcp.CacheHints{}, 100)

	if len(out) != 1 || out[0].Status != Info {
		t.Fatalf("want an observation on a small catalogue, got %+v", out)
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
