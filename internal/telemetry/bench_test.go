// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package telemetry

import (
	"fmt"
	"math/rand/v2"
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

// benchSecrets returns n distinct token-shaped values.
func benchSecrets(n int) []string {
	rng := rand.New(rand.NewPCG(1, uint64(n)))
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	out := make([]string, n)
	for i := range out {
		b := make([]byte, 24+rng.IntN(16))
		for j := range b {
			b[j] = alphabet[rng.IntN(len(alphabet))]
		}
		out[i] = string(b)
	}
	return out
}

// benchText is 64 KiB of JSON-like text that repeats some of values.
func benchText(values []string) string {
	rng := rand.New(rand.NewPCG(2, 2))
	var b strings.Builder
	for b.Len() < 64<<10 {
		fmt.Fprintf(&b, `{"id":%d,"text":"ordinary result text %d","url":"https://example.org/p?q=%d"},`, rng.IntN(1e6), rng.IntN(1e6), rng.IntN(1e6))
		if len(values) > 0 && rng.IntN(20) == 0 {
			b.WriteString(values[rng.IntN(len(values))])
		}
	}
	return b.String()[:64<<10]
}

func BenchmarkRedactorString(b *testing.B) {
	for _, n := range []int{1, 10, 100, 1000} {
		secrets := benchSecrets(n)
		r := &Redactor{}
		for _, s := range secrets {
			r.Add(s)
		}
		text := benchText(secrets)
		b.Run(fmt.Sprintf("secrets=%d", n), func(b *testing.B) {
			b.SetBytes(int64(len(text)))
			for i := 0; i < b.N; i++ {
				_ = r.String(text)
			}
		})
	}
}

func BenchmarkRedactorPersonal(b *testing.B) {
	for _, n := range []int{10, 100} {
		values := benchSecrets(n)
		r := &Redactor{}
		for _, v := range values {
			r.addPersonal(v)
		}
		text := benchText(values)
		b.Run(fmt.Sprintf("values=%d", n), func(b *testing.B) {
			b.SetBytes(int64(len(text)))
			for i := 0; i < b.N; i++ {
				_ = r.String(text)
			}
		})
	}
}

func BenchmarkRedactorAdd(b *testing.B) {
	secrets := benchSecrets(1000)
	for i := 0; i < b.N; i++ {
		r := &Redactor{}
		for _, s := range secrets {
			r.Add(s)
			r.addPersonal(s)
		}
	}
}

func BenchmarkNormaliseKey(b *testing.B) {
	keys := []string{"email_address", "Phone-Number", "first name", "repository", "id"}
	for i := 0; i < b.N; i++ {
		_ = normaliseKey(keys[i%len(keys)])
	}
}
