// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package telemetry

import "net"

// harServerIP is the host half of a recorded remote address, for HAR's
// serverIPAddress. net.SplitHostPort understands the bracketed IPv6 form
// ("[::1]:443"); an address without a port is returned as it is.
func harServerIP(remote string) string {
	if host, _, err := net.SplitHostPort(remote); err == nil {
		return host
	}
	return remote
}
