// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package passmcp

import (
	"net/http"
	"time"

	"satellion.com/passmcp/transport"
)

// DefaultTimeout is Config.Timeout's value when it is left at zero.
//
// Config.Timeout bounds how long a request waits without progress: for the
// response to begin, and then between reads of its body. It applies only
// when Config.HTTPClient sets no Timeout of its own and the request's
// context has no deadline, both of which are the caller's decision and
// win.
//
// It is an idle bound rather than a total one on purpose. An MCP reply can
// be an event stream that stays open while a tool works, and a stream that
// keeps delivering events is making progress however long it runs; a
// server that has gone silent is not.
const DefaultTimeout = transport.DefaultIdleTimeout

// baseHTTP is the client an HTTP Client is built on and the transport at
// the bottom of its chain. When nothing bounds its requests (no
// HTTPClient, or one without a Timeout), the transport gets the idle
// bound Config.Timeout asks for, so a server that stops answering cannot
// hold a caller that passed no deadline for ever.
func baseHTTP(cfg Config) (*http.Client, http.RoundTripper) {
	base := http.DefaultClient
	if cfg.HTTPClient != nil {
		base = cfg.HTTPClient
	}
	rt := base.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	if base.Timeout == 0 {
		rt = transport.IdleTimeout(rt, idleTimeout(cfg.Timeout))
	}
	return base, rt
}

// idleTimeout is the idle bound Config.Timeout asks for: zero is the
// default and a negative value is none.
func idleTimeout(d time.Duration) time.Duration {
	if d == 0 {
		return DefaultTimeout
	}
	return max(d, 0)
}
