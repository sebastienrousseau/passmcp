// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cra

import (
	"fmt"
	"strings"
	"time"
)

// MinExpiryHeadroom is how long a security.txt must still be valid for. A
// build that ships one expiring sooner fails, so renewing it is a routine
// change rather than an outage: RFC 9116 says an expired file must not be
// trusted.
const MinExpiryHeadroom = 30 * 24 * time.Hour

// CheckSecurityTxt returns what an RFC 9116 security.txt lacks for the
// site's policy: a Contact, a Policy pointing at the live security policy,
// a Canonical location, and an Expires date at least MinExpiryHeadroom
// after now. Field names are matched case-insensitively, as the RFC
// requires.
func CheckSecurityTxt(text string, now time.Time) []string {
	fields := map[string][]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(name))
		fields[key] = append(fields[key], strings.TrimSpace(value))
	}
	var problems []string
	for _, f := range []string{"contact", "policy", "canonical"} {
		if len(fields[f]) == 0 {
			problems = append(problems, "security.txt has no "+strings.ToUpper(f[:1])+f[1:]+" field")
		}
	}
	return append(problems, expiryProblems(fields["expires"], now)...)
}

// expiryProblems checks the single Expires field.
func expiryProblems(values []string, now time.Time) []string {
	if len(values) != 1 {
		return []string{fmt.Sprintf("security.txt must have exactly one Expires field, has %d", len(values))}
	}
	at, err := time.Parse(time.RFC3339, values[0])
	if err != nil {
		return []string{"security.txt Expires is not an RFC 3339 date: " + values[0]}
	}
	if left := at.Sub(now); left < MinExpiryHeadroom {
		return []string{fmt.Sprintf("security.txt expires %s, less than 30 days away; renew it", at.Format("2006-01-02"))}
	}
	return nil
}
