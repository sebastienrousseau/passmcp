// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package passmcp

import (
	"net/http"

	"satellion.com/passmcp/transport"
)

func wrap404OnSession(f *fakeStack, dead string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp" && r.Header.Get(transport.HeaderSessionID) == dead {
			w.WriteHeader(404)
			return
		}
		f.handleMCP(w, r)
	})
}
