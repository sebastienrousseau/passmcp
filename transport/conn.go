// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import "context"

// Conn is a JSON-RPC connection to one MCP server, however it is reached.
//
// Both transports satisfy it: Streamable over HTTP, and Stdio over a child
// process's pipes. The interface exists so a Client, and the phases that
// run through one, do not have to know which — most of what a diagnostic
// does is the same either way.
//
// What is deliberately absent is Do. The raw HTTP probe the protocol phase
// uses to send a malformed body or a bogus session header has no meaning on
// a pipe, and putting it here would force Stdio to carry a method it can
// only fail. A caller that needs it asks for the HTTP transport by type,
// which is honest about being HTTP-specific.
type Conn interface {
	// Call sends a request and decodes the result.
	Call(ctx context.Context, method string, params any, result any) error
	// Notify sends a notification, which expects no response.
	Notify(ctx context.Context, method string, params any) error

	// Dialect reports the protocol binding in use, and SetDialect changes
	// it. Both generations run over either transport.
	Dialect() Dialect
	SetDialect(d Dialect)

	// ProtocolVersion is the negotiated version.
	ProtocolVersion() string
	SetProtocolVersion(v string)

	// SessionID is the server-assigned session, which only a stateful
	// dialect over HTTP ever has. Stdio answers "" and accepts a set
	// without effect, so a caller written for one works against the other.
	SessionID() string
	SetSessionID(id string)

	// NextID allocates the next JSON-RPC request id, for a caller building
	// a raw message.
	NextID() int64

	// Reset drops per-session state.
	Reset()
}

// Both transports are connections. A compile-time assertion rather than a
// comment, so a method added to one and not the other stops the build here
// instead of at the first caller that notices.
var (
	_ Conn = (*Streamable)(nil)
	_ Conn = (*Stdio)(nil)
)
