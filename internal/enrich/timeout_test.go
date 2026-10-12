// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package enrich

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"satellion.com/passmcp/transport"
)

// silentServer accepts every request and never answers it, until the test
// ends.
func silentServer(t *testing.T) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	return srv
}

// TestNoClientDoesNotWaitForeverOnASilentAPI: an Anthropic with no Client
// used http.DefaultClient, which has no timeout, so an API that accepted the
// connection and never answered held the run open for ever.
func TestNoClientDoesNotWaitForeverOnASilentAPI(t *testing.T) {
	srv := silentServer(t)
	defer func(d time.Duration) { idleTimeout = d }(idleTimeout)
	idleTimeout = 100 * time.Millisecond

	done := make(chan error, 1)
	go func() {
		_, err := (&Anthropic{URL: srv.URL, Model: "m"}).Explain(context.Background(), []Item{{ID: "a"}})
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, transport.ErrIdle) {
			t.Fatalf("err = %v, want the idle timeout", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Explain was still waiting on a server that never answers after 5s")
	}
}

// roundTripFunc lets a test see that its own transport was the one used.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestACallerClientIsUsedAsGiven: the bound is for the fallback only. A
// client the caller supplied is used as it is, its transport not wrapped.
func TestACallerClientIsUsedAsGiven(t *testing.T) {
	srv := silentServer(t)
	used := false
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		used = true
		return nil, errors.New("caller transport")
	})
	c := &http.Client{Transport: rt}
	a := &Anthropic{URL: srv.URL, Model: "m", Client: c}
	if _, err := a.Explain(context.Background(), nil); err == nil || !used {
		t.Fatalf("err = %v, used = %v; the caller's client was not the one used", err, used)
	}
	if a.Client != c || c.Timeout != 0 {
		t.Error("the caller's client was replaced or changed")
	}
	if _, ok := c.Transport.(roundTripFunc); !ok {
		t.Errorf("the caller's transport was wrapped: %T", c.Transport)
	}
}
