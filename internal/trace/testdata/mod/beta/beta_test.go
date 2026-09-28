// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package beta

import "testing"

// AC: BETA-02
func TestFails(t *testing.T) { t.Fatal("deliberately failing fixture") }

// AC: BETA-01
func FuzzCited(f *testing.F) {
	f.Add("x")
	f.Fuzz(func(t *testing.T, s string) {})
}
