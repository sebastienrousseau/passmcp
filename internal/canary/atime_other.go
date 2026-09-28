// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build !darwin && !linux

package canary

import "time"

// accessTime is not available here.
//
// Windows keeps a last-access time and disables updating it by default,
// and the remaining platforms each spell the field differently for a
// witness that would be unreliable anyway. Reporting that passmcp cannot
// tell is the honest answer, and the check that reads this says so rather
// than reporting that nothing was found.
func accessTime(string) (time.Time, bool) { return time.Time{}, false }
