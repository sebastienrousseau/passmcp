// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package pii

import "testing"

func TestNormaliseAndKey(t *testing.T) {
	for in, want := range map[string]bool{
		"Patient_Name": true, "billing-address": true, "contact.name": true, "E Mail Address": true,
		"NINO": true, "name": true, "repository": false, "ip_address": false, "": false,
	} {
		if got := Key(Normalise(in)); got != want {
			t.Errorf("Key(Normalise(%q)) = %t, want %t", in, got, want)
		}
	}
	if got := Normalise("Patient_Name-x.y z"); got != "patientnamexyz" {
		t.Errorf("Normalise = %q", got)
	}
}

func BenchmarkNormalise(b *testing.B) {
	keys := []string{"email_address", "Phone-Number", "first name", "customer.name", "repository"}
	for i := 0; i < b.N; i++ {
		_ = Normalise(keys[i%len(keys)])
	}
}
