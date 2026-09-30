// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultIdleTimeout is how long a request made without a deadline may go
// without progress before it is abandoned, when the caller set no bound of
// its own.
const DefaultIdleTimeout = 60 * time.Second

// ErrIdle is wrapped by the error a request fails with when IdleTimeout
// abandons it.
var ErrIdle = errors.New("transport: no progress from the server within the idle timeout")

// IdleTimeout wraps base so that a request whose context carries no
// deadline is abandoned after d without progress: d waiting for the
// response to begin, then d between reads of its body.
//
// http.Client.Timeout bounds the whole exchange, body included, which is
// wrong for an MCP reply: a POST can be answered with an event stream that
// stays open while a tool works, and a stream still delivering events is
// working however long it runs. What should end is a server that has gone
// silent, so each read that returns data starts the clock again.
//
// A request whose context already has a deadline is passed through
// untouched: the caller chose how long to wait, and it may be longer. A d
// of zero or less returns base unwrapped.
func IdleTimeout(base http.RoundTripper, d time.Duration) http.RoundTripper {
	if d <= 0 {
		return base
	}
	if base == nil {
		base = http.DefaultTransport
	}
	return idleTransport{base: base, d: d}
}

type idleTransport struct {
	base http.RoundTripper
	d    time.Duration
}

// RoundTrip sends r, abandoning it after d without progress.
func (t idleTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if _, ok := r.Context().Deadline(); ok {
		return t.base.RoundTrip(r)
	}
	ctx, cancel := context.WithCancelCause(r.Context())
	cause := fmt.Errorf("%w (%s)", ErrIdle, t.d)
	timer := time.AfterFunc(t.d, func() { cancel(cause) })
	resp, err := t.base.RoundTrip(r.WithContext(ctx))
	if err != nil {
		timer.Stop()
		cancel(nil)
		return nil, idleCause(ctx, err)
	}
	resp.Body = &idleBody{rc: resp.Body, ctx: ctx, timer: timer, d: t.d, cancel: cancel}
	return resp, nil
}

// idleCause replaces a cancellation the idle timer caused with the reason.
func idleCause(ctx context.Context, err error) error {
	if c := context.Cause(ctx); c != nil && errors.Is(c, ErrIdle) {
		return fmt.Errorf("%w: %w", c, err)
	}
	return err
}

// idleBody restarts the idle timer on every read that returns data, and
// releases the request's context when it is closed.
type idleBody struct {
	rc     io.ReadCloser
	ctx    context.Context
	timer  *time.Timer
	d      time.Duration
	cancel context.CancelCauseFunc
}

// Read reads from the body and restarts the idle timer when data came.
func (b *idleBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if n > 0 {
		b.timer.Reset(b.d)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		err = idleCause(b.ctx, err)
	}
	return n, err
}

// Close stops the timer, closes the body and releases the context.
func (b *idleBody) Close() error {
	b.timer.Stop()
	err := b.rc.Close()
	b.cancel(nil)
	return err
}
