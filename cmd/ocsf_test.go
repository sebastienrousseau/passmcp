// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// AC: OCSF-05
func TestOCSFGoesOnlyToTheNamedEndpointAndIsAnnouncedFirst(t *testing.T) {
	f := newFakeServer(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var posts atomic.Int32
	var body, auth string
	siem := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		b, _ := io.ReadAll(r.Body)
		body, auth = string(b), r.Header.Get("Authorization")
	}))
	defer siem.Close()
	base := []string{"check", f.srv.URL + "/mcp", "--auth", "client-credentials", "--client-id", "cid",
		"--client-secret", "sec", "--param", "profile_id=t1", "--rps", "0", "--samples", "1", "--concurrency", "2"}

	// Without the flag nothing is sent anywhere.
	out, _, _ := runCapturingStderr(t, append(base, "--output", "ocsf")...)
	if posts.Load() != 0 {
		t.Fatal("OCSF events were sent without --ocsf-endpoint")
	}
	var events []map[string]any
	if err := json.Unmarshal([]byte(out), &events); err != nil || len(events) == 0 {
		t.Fatalf("--output ocsf prints a non-empty event array: %v\n%s", err, out)
	}
	if events[0]["metadata"].(map[string]any)["version"] != "1.3.0" {
		t.Errorf("events carry the pinned schema version: %v", events[0]["metadata"])
	}

	// With it, the destination is announced on stderr and the events go
	// there and nowhere else.
	_, stderr, _ := runCapturingStderr(t, append(base, "--output", "json", "--log-level", "info",
		"--ocsf-endpoint", siem.URL, "--ocsf-header", "Authorization: Splunk hec-token")...)
	if posts.Load() != 1 {
		t.Fatalf("want one POST to the named endpoint, got %d", posts.Load())
	}
	if !strings.Contains(stderr, "OCSF event(s) to "+siem.URL) {
		t.Errorf("the destination must be announced on stderr:\n%s", stderr)
	}
	if auth != "Splunk hec-token" {
		t.Errorf("the operator's header must reach the collector: %q", auth)
	}
	if strings.Contains(stderr, "hec-token") {
		t.Error("the collector's token must never be printed")
	}
	if !strings.HasPrefix(strings.TrimSpace(body), "[") {
		t.Errorf("the body is the event array: %.80s", body)
	}
}

func TestOCSFExportFailureIsNotFatal(t *testing.T) {
	f := newFakeServer(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	_, stderr, _ := runCapturingStderr(t, "check", f.srv.URL+"/mcp", "--auth", "client-credentials", "--client-id", "cid",
		"--client-secret", "sec", "--param", "profile_id=t1", "--rps", "0", "--samples", "1",
		"--output", "json", "--ocsf-endpoint", "http://127.0.0.1:1/events", "--ocsf-header", "bad header")
	if !strings.Contains(stderr, "OCSF export failed") {
		t.Errorf("a failed export is reported as a warning:\n%s", stderr)
	}
}
