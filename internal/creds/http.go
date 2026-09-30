// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package creds

import "net/http"

// httpClient lets Source accept either a *http.Client or nil.
type httpClient interface{ client() *http.Client }

// HTTP wraps a client for StoredToken.Source.
type HTTP struct{ C *http.Client }

// client returns the wrapped client. A nil one is passed on as nil, so the
// auth package substitutes its own default, which has a timeout, rather
// than http.DefaultClient, which has none.
func (h HTTP) client() *http.Client { return h.C }
