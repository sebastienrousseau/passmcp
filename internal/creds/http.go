// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package creds

import "net/http"

// httpClient lets Source accept either a *http.Client or nil.
type httpClient interface{ client() *http.Client }

// HTTP wraps a client for StoredToken.Source.
type HTTP struct{ C *http.Client }

func (h HTTP) client() *http.Client {
	if h.C == nil {
		return http.DefaultClient
	}
	return h.C
}
