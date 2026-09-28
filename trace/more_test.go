// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package trace

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnsureKeepsExistingAndDefaultBase(t *testing.T) {
	ctx := WithID(context.Background(), "keep")
	if FromContext(Ensure(ctx)) != "keep" {
		t.Error("Ensure must not replace an existing id")
	}
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Get(Header) }))
	defer srv.Close()
	hc := &http.Client{Transport: RoundTripper{}}
	req, _ := http.NewRequestWithContext(WithID(context.Background(), "x"), "GET", srv.URL, nil)
	req.Header.Set(Header, "preset")
	if _, err := hc.Do(req); err != nil || got != "preset" {
		t.Errorf("preset header must win: %v %q", err, got)
	}
}
