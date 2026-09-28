// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package diagnostics

import (
	"slices"
	"time"
)

// Latencies accumulates call durations and computes percentiles.
type Latencies struct {
	samples []time.Duration
}

// Add records one sample.
func (l *Latencies) Add(d time.Duration) { l.samples = append(l.samples, d) }

// Len returns the sample count.
func (l *Latencies) Len() int { return len(l.samples) }

// Percentile returns the nearest-rank percentile (0 < p <= 100). It
// returns 0 with no samples.
func (l *Latencies) Percentile(p float64) time.Duration {
	if len(l.samples) == 0 {
		return 0
	}
	sorted := slices.Clone(l.samples)
	slices.Sort(sorted)
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	rank := int(float64(len(sorted))*p/100 + 0.999999)
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}

// Max returns the largest sample.
func (l *Latencies) Max() time.Duration { return l.Percentile(100) }

// Summary is the percentile digest included in reports.
type Summary struct {
	Count int           `json:"count"`
	P50   time.Duration `json:"p50"`
	P95   time.Duration `json:"p95"`
	P99   time.Duration `json:"p99"`
	Max   time.Duration `json:"max"`
}

// Summarize computes the digest.
func (l *Latencies) Summarize() Summary {
	return Summary{Count: l.Len(), P50: l.Percentile(50), P95: l.Percentile(95), P99: l.Percentile(99), Max: l.Max()}
}

// IsOutlier reports whether d is anomalous relative to the median: at
// least factor times the median and above floor. It needs a minimum of
// three samples to say anything.
func (l *Latencies) IsOutlier(d time.Duration, factor float64, floor time.Duration) bool {
	if len(l.samples) < 3 || d < floor {
		return false
	}
	med := l.Percentile(50)
	if med == 0 {
		return d >= floor
	}
	return float64(d) >= float64(med)*factor
}
