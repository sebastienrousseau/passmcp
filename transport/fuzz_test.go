// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import (
	"strings"
	"testing"
)

func FuzzReadSSE(f *testing.F) {
	f.Add("data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n", int64(1))
	f.Add(": keepalive\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\ndata: \"result\":{\"a\":1}}\n\n", int64(7))
	f.Add("data: not json\n\n", int64(1))
	f.Add("", int64(0))
	f.Fuzz(func(t *testing.T, body string, id int64) {
		res, err := readSSEResponse(strings.NewReader(body), id)
		if err == nil && res != nil && res.ID != nil && *res.ID != id {
			t.Fatalf("returned response for wrong id: %d != %d", *res.ID, id)
		}
	})
}
