// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"fmt"
	"math"
)

// The ceilings on how hard a run may push. passmcp is a diagnostic run
// against a server somebody else operates, and these flags are the load it
// places there: past these figures a value is a typo or a load test, and
// passmcp is not a load-testing tool. Zero and negative rates remain the
// documented way to switch the throttle off, and --allow-load still runs
// the burst unthrottled.
const (
	// MaxRPS is the highest --rps accepted.
	MaxRPS = 100
	// MaxConcurrency is the most workers --concurrency may start.
	MaxConcurrency = 64
	// NoBurst is the PacingSpec.Concurrency that runs no parallel burst.
	NoBurst = -1
)

// ValidatePace checks a request rate and a worker count against MaxRPS and
// MaxConcurrency. It is exported so every command with these flags refuses
// the same values with the same words.
func ValidatePace(rps float64, concurrency int) error {
	if math.IsNaN(rps) || rps > MaxRPS {
		return fmt.Errorf("--rps %v is above the maximum of %d requests per second; passmcp is a diagnostic, not a load test (0 switches the throttle off, and --allow-load runs the burst unthrottled)", rps, MaxRPS)
	}
	if concurrency > MaxConcurrency {
		return fmt.Errorf("--concurrency %d is above the maximum of %d workers; passmcp is a diagnostic, not a load test", concurrency, MaxConcurrency)
	}
	return nil
}
