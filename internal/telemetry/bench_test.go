// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package telemetry

import "testing"

func BenchmarkRedactJSON(b *testing.B) {
	r := &Redactor{}
	r.Add("a-long-secret-value")
	body := []byte(`{"access_token":"tok","refresh_token":"rt","nested":{"client_secret":"a-long-secret-value","list":[{"code":"x"}]},"ok":"keep"}`)
	for i := 0; i < b.N; i++ {
		_ = r.JSON(body)
	}
}
