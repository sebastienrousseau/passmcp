// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build windows

package watch

import (
	"fmt"
	"testing"
)

// TestWinsockErrnosAreClassified: a refused or reset connection on Windows
// carries Winsock's own error number, wrapped as a dial error would be.
func TestWinsockErrnosAreClassified(t *testing.T) {
	if !isConnRefused(fmt.Errorf("dial tcp: connectex: %w", wsaECONNREFUSED)) {
		t.Error("WSAECONNREFUSED is not classified as a refused connection")
	}
	if !isConnReset(fmt.Errorf("read tcp: wsarecv: %w", wsaECONNRESET)) {
		t.Error("WSAECONNRESET is not classified as a reset connection")
	}
}
