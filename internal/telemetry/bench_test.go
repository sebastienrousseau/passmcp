// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package telemetry

import (
	"fmt"
	"strings"
	"testing"
)

func BenchmarkRedactJSON(b *testing.B) {
	r := &Redactor{}
	r.Add("a-long-secret-value")
	body := []byte(`{"access_token":"tok","refresh_token":"rt","nested":{"client_secret":"a-long-secret-value","list":[{"code":"x"}]},"ok":"keep"}`)
	for i := 0; i < b.N; i++ {
		_ = r.JSON(body)
	}
}

// benchBody is a tools/call result of about 16 KiB carrying one token.
func benchBody() []byte {
	var b strings.Builder
	b.WriteString(`{"jsonrpc":"2.0","id":7,"result":{"access_token":"tok-bench-0001","content":[`)
	for i := 0; i < 160; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"type":"text","text":"line %d of the result, ordinary text","n":%d}`, i, i)
	}
	b.WriteString(`]}}`)
	return []byte(b.String())
}

func BenchmarkJSONOrKeys(b *testing.B) {
	body := benchBody()
	b.Run("valid", func(b *testing.B) {
		r := &Redactor{}
		for i := 0; i < b.N; i++ {
			_ = r.JSONOrKeys(body)
		}
	})
	b.Run("truncated", func(b *testing.B) {
		r := &Redactor{}
		for i := 0; i < b.N; i++ {
			_ = r.JSONOrKeys(body[:len(body)-40])
		}
	})
}

func BenchmarkNormaliseKey(b *testing.B) {
	keys := []string{"email_address", "Phone-Number", "first name", "repository", "id"}
	for i := 0; i < b.N; i++ {
		_ = normaliseKey(keys[i%len(keys)])
	}
}
