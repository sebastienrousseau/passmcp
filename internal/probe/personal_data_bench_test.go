// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import "testing"

func BenchmarkPersonalField(b *testing.B) {
	names := []string{"email_address", "Phone-Number", "customer.name", "repository", "ip_address"}
	for i := 0; i < b.N; i++ {
		_ = personalField(names[i%len(names)], "the customer's contact")
	}
}
