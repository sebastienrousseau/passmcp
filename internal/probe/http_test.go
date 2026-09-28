// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import "net/http"

type (
	httpResponseWriter = http.ResponseWriter
	httpRequest        = *http.Request
)

func httpHandlerFunc(f func(httpResponseWriter, httpRequest)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f(w, r) })
}
