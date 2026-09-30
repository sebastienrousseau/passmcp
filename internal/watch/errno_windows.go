// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build windows

package watch

import (
	"errors"
	"syscall"
)

// Winsock's error numbers for these two conditions. The syscall package
// does not export them, and the POSIX constants do not match them.
const (
	wsaECONNRESET   syscall.Errno = 10054
	wsaECONNREFUSED syscall.Errno = 10061
)

// isConnRefused reports a connection the peer refused.
func isConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, wsaECONNREFUSED)
}

// isConnReset reports a connection the peer reset.
func isConnReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, wsaECONNRESET)
}
