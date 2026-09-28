// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build passmcp_trace_fixture_no_platform

package beta

import "testing"

// TestElsewhere builds on no platform this suite runs on, as a test that
// needs Linux does on a Mac: it cannot run here, so it is not a failure
// here.
//
// AC: BETA-01
func TestElsewhere(t *testing.T) {}
