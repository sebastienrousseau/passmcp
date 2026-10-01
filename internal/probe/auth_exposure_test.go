// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"strings"
	"testing"

	"satellion.com/passmcp/transport"
)

// TestUnauthenticatedToolsBranches covers the outcomes the end-to-end
// tests in phases_test.go do not reach: the two skips, a request that could
// not be made, a reply that is not a tool list, an empty catalogue, and the
// harsher lead for a server that challenged first contact and served the
// catalogue anyway. Each case starts from a run against an open fake and
// then changes the one thing it is about.
func TestUnauthenticatedToolsBranches(t *testing.T) {
	cases := []struct {
		name     string
		quirks   func(*quirks)
		mutate   func(*Session, *fakeServer)
		status   Status
		contains string
	}{
		{"over stdio", nil,
			func(s *Session, _ *fakeServer) { s.Pipe = &transport.Stdio{} },
			Skip, "a child process has no credentials to omit"},
		{"no bare transport", nil,
			func(s *Session, _ *fakeServer) { s.Bare = nil },
			Skip, "never reached without credentials"},
		{"never reached", nil,
			func(s *Session, _ *fakeServer) { s.Reached = false },
			Skip, "never reached without credentials"},
		{"request failed", nil,
			func(_ *Session, f *fakeServer) { f.srv.Close() },
			Info, "could not ask without credentials"},
		{"unreadable listing",
			func(q *quirks) { q.extraTools = []map[string]any{{"name": 5}} }, nil,
			Warn, "not a tool list"},
		{"empty catalogue",
			func(q *quirks) { q.catalog = "empty" }, nil,
			Pass, "returned no tools"},
		{"challenged then served", nil,
			func(s *Session, _ *fakeServer) { s.RequiresAuth = true },
			Warn, "answers 401 to first contact and still served"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeServer(t)
			f.q.open = true
			if tc.quirks != nil {
				tc.quirks(&f.q)
			}
			sess, _ := run(t, f, nil, func(o *Options) { o.Only = []string{"net", "discovery", "auth"} })
			if tc.mutate != nil {
				tc.mutate(sess, f)
			}
			got := checkUnauthenticatedTools(context.Background(), sess)
			if got.Status != tc.status || !strings.Contains(got.Detail, tc.contains) {
				t.Errorf("got %s %q, want %s containing %q", got.Status, got.Detail, tc.status, tc.contains)
			}
		})
	}
}
