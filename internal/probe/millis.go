// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"encoding/json"
	"time"
)

// Millis is a duration that marshals as fractional milliseconds, so a field
// tagged duration_ms holds milliseconds rather than the nanoseconds a bare
// time.Duration would emit. Every consumer of passmcp's JSON reads these
// numbers; they have to mean what the field name says.
type Millis time.Duration

// Duration returns the value as a time.Duration.
func (m Millis) Duration() time.Duration { return time.Duration(m) }

// String implements fmt.Stringer.
func (m Millis) String() string { return time.Duration(m).String() }

// MarshalJSON implements json.Marshaler, rendering fractional milliseconds.
func (m Millis) MarshalJSON() ([]byte, error) {
	return json.Marshal(float64(m) / float64(time.Millisecond))
}

// UnmarshalJSON implements json.Unmarshaler, reading fractional
// milliseconds back into a duration so a report round-trips.
func (m *Millis) UnmarshalJSON(b []byte) error {
	var f float64
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	*m = Millis(f * float64(time.Millisecond))
	return nil
}
