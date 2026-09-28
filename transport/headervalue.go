// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import (
	"encoding/base64"
	"strings"
)

// Base64 sentinel markers. They are case-sensitive and must appear exactly
// as written.
const (
	sentinelPrefix = "=?base64?"
	sentinelSuffix = "?="
)

// EncodeHeaderValue renders v for an HTTP header, using the 2026-07-28
// Base64 sentinel form when v cannot be carried as a plain field value.
//
// RFC 9110 restricts a field value to visible ASCII, space and horizontal
// tab, with no leading or trailing whitespace. Tool and prompt names are
// only SHOULD-constrained to that set and a resource URI is not constrained
// at all, so a name outside it — or one that would be mistaken for the
// sentinel — is encoded rather than smuggled into the header.
func EncodeHeaderValue(v string) string {
	if headerSafe(v) {
		return v
	}
	return sentinelPrefix + base64.StdEncoding.EncodeToString([]byte(v)) + sentinelSuffix
}

// DecodeHeaderValue reverses EncodeHeaderValue. A value that is not in the
// sentinel form is returned unchanged; one that claims to be but does not
// decode is reported.
func DecodeHeaderValue(v string) (string, bool) {
	if !strings.HasPrefix(v, sentinelPrefix) || !strings.HasSuffix(v, sentinelSuffix) {
		return v, true
	}
	body := v[len(sentinelPrefix) : len(v)-len(sentinelSuffix)]
	b, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return v, false
	}
	return string(b), true
}

// headerSafe reports whether v can be sent verbatim as a field value.
func headerSafe(v string) bool {
	if v == "" {
		return true
	}
	// A plain-ASCII value that looks like the sentinel must still be
	// encoded, or a receiver would decode something the sender never
	// encoded.
	if strings.HasPrefix(v, sentinelPrefix) && strings.HasSuffix(v, sentinelSuffix) {
		return false
	}
	if v[0] == ' ' || v[0] == '\t' || v[len(v)-1] == ' ' || v[len(v)-1] == '\t' {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '\t' {
			continue
		}
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}
