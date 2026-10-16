// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package telemetry

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

// serverIPAddress is the host half of the connection's remote address.
// Splitting on the first colon cut an IPv6 address down to "[".
func TestHARServerIPAddress(t *testing.T) {
	for remote, want := range map[string]string{
		"127.0.0.1:443":         "127.0.0.1",
		"[::1]:443":             "::1",
		"[2001:db8::1]:8443":    "2001:db8::1",
		"[fe80::1%en0]:443":     "fe80::1%en0",
		"":                      "",
		"no-port-recorded-here": "no-port-recorded-here",
	} {
		rec := New()
		rec.add(Event{Time: time.Now(), Method: "GET", URL: "http://x/", Status: 200, Remote: remote})
		var buf bytes.Buffer
		if err := rec.WriteHAR(&buf, "t"); err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Log struct {
				Entries []struct {
					ServerIPAddress string `json:"serverIPAddress"`
				} `json:"entries"`
			} `json:"log"`
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil || len(doc.Log.Entries) != 1 {
			t.Fatalf("HAR for %q: %v, %d entries", remote, err, len(doc.Log.Entries))
		}
		if got := doc.Log.Entries[0].ServerIPAddress; got != want {
			t.Errorf("serverIPAddress for %q = %q, want %q", remote, got, want)
		}
	}
}
