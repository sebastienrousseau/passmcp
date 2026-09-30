// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// pacedServer writes n events, pause apart, after waiting first.
func pacedServer(t *testing.T, first, pause time.Duration, n int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(first):
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for i := range n {
			_, _ = fmt.Fprintf(w, "data: %d\n\n", i)
			w.(http.Flusher).Flush()
			select {
			case <-time.After(pause):
			case <-r.Context().Done():
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, rt http.RoundTripper, ctx context.Context, url string) (string, error) {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := (&http.Client{Transport: rt}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func TestIdleTimeoutAbandonsASilentServer(t *testing.T) {
	srv := pacedServer(t, time.Hour, 0, 1)
	start := time.Now()
	_, err := get(t, IdleTimeout(nil, 50*time.Millisecond), context.Background(), srv.URL)
	if !errors.Is(err, ErrIdle) {
		t.Fatalf("err = %v, want ErrIdle", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("took %s to give up", time.Since(start))
	}
}

func TestIdleTimeoutAbandonsAStreamThatGoesSilent(t *testing.T) {
	srv := pacedServer(t, 0, time.Hour, 2)
	_, err := get(t, IdleTimeout(nil, 50*time.Millisecond), context.Background(), srv.URL)
	if !errors.Is(err, ErrIdle) {
		t.Fatalf("a stream that stopped sending was not abandoned: %v", err)
	}
}

// TestIdleTimeoutKeepsAStreamThatMakesProgress is the reason the bound is
// on silence rather than on the whole exchange: this stream runs for twice
// the timeout or more and is never idle for one.
func TestIdleTimeoutKeepsAStreamThatMakesProgress(t *testing.T) {
	srv := pacedServer(t, 0, 20*time.Millisecond, 20)
	body, err := get(t, IdleTimeout(nil, 200*time.Millisecond), context.Background(), srv.URL)
	if err != nil || strings.Count(body, "data:") != 20 {
		t.Fatalf("a live stream was cut: %v after %q", err, body)
	}
}

// TestIdleTimeoutDefersToTheCallersDeadline: a caller who set a deadline
// chose how long to wait, and it may be longer than the idle bound.
func TestIdleTimeoutDefersToTheCallersDeadline(t *testing.T) {
	srv := pacedServer(t, 150*time.Millisecond, 0, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := get(t, IdleTimeout(nil, 50*time.Millisecond), ctx, srv.URL); err != nil {
		t.Fatalf("a request with its own deadline was cut by the idle bound: %v", err)
	}
	if rt := IdleTimeout(http.DefaultTransport, 0); rt != http.DefaultTransport {
		t.Error("a zero idle timeout must leave the transport unwrapped")
	}
}

func TestNewWithoutAClientIsBounded(t *testing.T) {
	s := New("http://127.0.0.1:1/mcp", nil)
	if _, ok := s.Client.Transport.(idleTransport); !ok || s.Client.Transport.(idleTransport).d != DefaultIdleTimeout {
		t.Errorf("default client transport = %#v", s.Client.Transport)
	}
}
