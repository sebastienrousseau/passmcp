// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import (
	"fmt"
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

// FuzzHeaderValue holds the parameter header encoder to its two promises
// for any string a server's schema or arguments could supply: the encoded
// form is a legal HTTP field value, and decoding it gives back the input.
func FuzzHeaderValue(f *testing.F) {
	for _, seed := range []string{
		"",
		"search_repositories",
		"café ☕",
		"line one\r\nX-Injected: yes",
		"=?base64?aGVsbG8=?=",
		" padded\t",
		"tab\tinside",
		"\x00\x7f",
		"del\x7f",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, v string) {
		enc := EncodeHeaderValue(v)
		if bad := illegalFieldValue(enc); bad != "" {
			t.Fatalf("EncodeHeaderValue(%q) = %q, not a legal field value: %s", v, enc, bad)
		}
		got, ok := DecodeHeaderValue(enc)
		if !ok || got != v {
			t.Fatalf("DecodeHeaderValue(EncodeHeaderValue(%q)) = %q, %t; want the input back", v, got, ok)
		}
	})
}

// illegalFieldValue states RFC 9110's field-value rule independently of
// headerSafe, so a mistake in the encoder cannot be hidden by the same
// mistake in its check: visible ASCII, space and horizontal tab only, and
// no leading or trailing whitespace. It returns why v breaks the rule, or
// "" when it does not.
func illegalFieldValue(v string) string {
	if v == "" {
		return ""
	}
	if strings.ContainsAny(v[:1]+v[len(v)-1:], " \t") {
		return "leading or trailing whitespace"
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; c != '\t' && (c < 0x20 || c > 0x7e) {
			return fmt.Sprintf("byte %#x at offset %d", c, i)
		}
	}
	return ""
}
