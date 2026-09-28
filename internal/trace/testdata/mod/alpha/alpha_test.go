// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package alpha

import "testing"

// TestBoth proves two criteria at once.
//
// AC: ALPHA-01, BETA-01
func TestBoth(t *testing.T) {}

// AC: GHOST-01
func TestOrphan(t *testing.T) {}

// AC: not-an-id
func TestMalformed(t *testing.T) {}

// AC: ALPHA-02
func helperNotATest() {}

type suite struct{}

// AC: ALPHA-02
func (suite) TestMethod(t *testing.T) {}
