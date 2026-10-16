// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package telemetry

import "testing"

// TestSensitiveHeaderNames: one rule decides which header values are
// credentials, for the recorder's masking and for the secrets an operator's
// --header values register.
func TestSensitiveHeaderNames(t *testing.T) {
	for name, want := range map[string]bool{
		"Authorization": true, "Proxy-Authorization": true, "Cookie": true, "Set-Cookie": true,
		"X-API-Key": true, "X-Auth-Token": true, "X-Client-Secret": true, "X-Password": true,
		"X-Auth": true, "Content-Type": false, "X-Tenant": false, "Accept": false,
	} {
		if got := SensitiveHeader(name); got != want {
			t.Errorf("SensitiveHeader(%q) = %v, want %v", name, got, want)
		}
	}
	r := &Redactor{}
	if got := r.Header("X-Password", "hunter2-but-longer"); got != Mask {
		t.Errorf("X-Password value printed as %q", got)
	}
}
