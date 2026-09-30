// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package passmcp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"satellion.com/passmcp/transport"
)

// silentServer accepts every request and never answers it.
func silentServer(t *testing.T) *httptest.Server {
	t.Helper()
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-done:
		}
	}))
	t.Cleanup(func() { close(done); srv.Close() })
	return srv
}

// TestDefaultClientDoesNotWaitForeverOnASilentServer: a library caller
// that supplies no HTTPClient and no deadline used to get
// http.DefaultClient, which has no timeout, and a server that accepts the
// connection and never answers held Connect for ever.
func TestDefaultClientDoesNotWaitForeverOnASilentServer(t *testing.T) {
	srv := silentServer(t)
	c, err := New(Config{Endpoint: srv.URL + "/mcp", Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { _, err := c.Connect(context.Background()); errc <- err }()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("Connect to a silent server succeeded")
		}
		if !errors.Is(err, transport.ErrIdle) {
			t.Errorf("error does not say why: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Connect to a silent server was still waiting after 5s with a 100ms timeout")
	}
}

// TestTimeoutLeavesTheCallersChoicesAlone: an HTTPClient with its own
// Timeout, a context with its own deadline and a negative Timeout are each
// the caller deciding, and none is overridden by the idle bound.
func TestTimeoutLeavesTheCallersChoicesAlone(t *testing.T) {
	srv := silentServer(t)
	connect := func(cfg Config, d time.Duration) error {
		c, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), d)
		defer cancel()
		_, err = c.Connect(ctx)
		return err
	}
	for name, cfg := range map[string]Config{
		"own client timeout": {Endpoint: srv.URL + "/mcp", Timeout: 10 * time.Millisecond, HTTPClient: &http.Client{Timeout: time.Minute}},
		"negative timeout":   {Endpoint: srv.URL + "/mcp", Timeout: -1},
		"context deadline":   {Endpoint: srv.URL + "/mcp", Timeout: 10 * time.Millisecond},
	} {
		if err := connect(cfg, 300*time.Millisecond); err == nil || errors.Is(err, transport.ErrIdle) {
			t.Errorf("%s: the idle bound fired, or nothing did: %v", name, err)
		}
	}
	if idleTimeout(0) != DefaultTimeout || idleTimeout(-1) != 0 || idleTimeout(time.Second) != time.Second {
		t.Error("idleTimeout mapping")
	}
}
