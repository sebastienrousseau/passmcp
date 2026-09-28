// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCallOnAcknowledgedRequest is the regression for a nil dereference:
// send returns (nil, nil) for 202 and 204, which are the notification
// acknowledgements, and Call dereferenced the result unconditionally. A
// server that answered an id-bearing request that way crashed passmcp with a
// stack trace instead of producing the finding that says so — the exact
// failure the tool exists to report.
func TestCallOnAcknowledgedRequest(t *testing.T) {
	for _, code := range []int{http.StatusAccepted, http.StatusNoContent} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(code)
			}))
			defer srv.Close()
			var out map[string]any
			err := New(srv.URL, srv.Client()).Call(context.Background(), "initialize", map[string]any{}, &out)
			if !errors.Is(err, ErrNoResponse) {
				t.Fatalf("want ErrNoResponse, got %v", err)
			}
			if !strings.Contains(err.Error(), "initialize") {
				t.Errorf("error should name the method: %v", err)
			}
		})
	}
}

// A notification legitimately gets 202 and must not become an error.
func TestNotifyAcceptsAcknowledgement(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	if err := New(srv.URL, srv.Client()).Notify(context.Background(), "notifications/initialized", nil); err != nil {
		t.Fatalf("a notification may be acknowledged: %v", err)
	}
}

// TestResponseBodyIsBounded: an unbounded decode lets a server passmcp was
// pointed at exhaust the client's memory.
func TestResponseBodyIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		chunk := strings.Repeat("a", 1<<20)
		for i := 0; i < MaxResponseBytes/(1<<20)+8; i++ {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	var out map[string]any
	err := New(srv.URL, srv.Client()).Call(context.Background(), "initialize", nil, &out)
	if err == nil {
		t.Fatal("a body that never ends must be an error, not an allocation")
	}
}

// TestStreamEventsAreBounded: an SSE stream that never carries the response
// must end in an error rather than spinning forever.
func TestStreamEventsAreBounded(t *testing.T) {
	r := strings.NewReader(strings.Repeat(": keep-alive\n\n", MaxStreamEvents+10))
	if _, err := readSSEResponse(r, 1); !errors.Is(err, ErrStreamTooLarge) {
		t.Fatalf("want ErrStreamTooLarge, got %v", err)
	}
}
