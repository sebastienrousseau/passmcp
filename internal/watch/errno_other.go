// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build !windows

package watch

import (
	"errors"
	"syscall"
)

// isConnRefused reports a connection the peer refused.
func isConnRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

// isConnReset reports a connection the peer reset.
func isConnReset(err error) bool { return errors.Is(err, syscall.ECONNRESET) }
