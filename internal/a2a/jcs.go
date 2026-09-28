// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package a2a

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Canonicalize returns the RFC 8785 JSON Canonicalization Scheme form of a
// JSON document.
//
// A2A signs the canonical form of an Agent Card, not the bytes on the wire,
// so a verifier that serialises differently from the signer rejects a card
// that is intact. RFC 8785 fixes the three places serialisers disagree:
// object members are sorted by their names as UTF-16 code units, numbers
// are written the way ECMAScript's Number.prototype.toString writes them,
// and strings escape only what JSON requires.
func Canonicalize(doc []byte) ([]byte, error) {
	v, err := decode(doc)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := writeCanonical(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// decode parses one JSON value, keeping numbers as written so their
// canonical form is computed from the value rather than a lossy float.
func decode(doc []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("jcs: %w", err)
	}
	if dec.More() {
		return nil, errors.New("jcs: trailing data after the JSON value")
	}
	return v, nil
}

// canonicalValue canonicalises a value already decoded with UseNumber.
func canonicalValue(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := writeCanonical(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeCanonical(b *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(t))
	case json.Number:
		s, err := canonicalNumber(t)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case string:
		writeString(b, t)
	case []any:
		return writeArray(b, t)
	case map[string]any:
		return writeObject(b, t)
	default:
		return fmt.Errorf("jcs: unsupported value of type %T", v)
	}
	return nil
}

func writeArray(b *bytes.Buffer, a []any) error {
	b.WriteByte('[')
	for i, e := range a {
		if i > 0 {
			b.WriteByte(',')
		}
		if err := writeCanonical(b, e); err != nil {
			return err
		}
	}
	b.WriteByte(']')
	return nil
}

func writeObject(b *bytes.Buffer, m map[string]any) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		writeString(b, k)
		b.WriteByte(':')
		if err := writeCanonical(b, m[k]); err != nil {
			return err
		}
	}
	b.WriteByte('}')
	return nil
}

// lessUTF16 orders member names by their UTF-16 code units, as RFC 8785
// section 3.2.3 requires. Go strings compare as UTF-8 bytes, which puts a
// character above U+FFFF (two UTF-16 surrogates, 0xD800-0xDFFF) after one
// in U+E000-U+FFFF; UTF-16 order puts it before.
func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// writeString escapes only what JSON requires (RFC 8785 section 3.2.2.2):
// the quote, the backslash and the control characters, using the short
// forms where JSON has them and lowercase \u00xx otherwise. Everything else,
// including '/' and every non-ASCII character, is written as UTF-8.
func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

// canonicalNumber writes a number as ECMAScript's Number.prototype.toString
// does for an IEEE 754 double (RFC 8785 section 3.2.2.3): the shortest
// digits that round-trip, positional between 1e-6 and 1e21, exponential
// outside it, and negative zero as 0.
func canonicalNumber(n json.Number) (string, error) {
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return "", fmt.Errorf("jcs: %q is not a finite IEEE 754 double", string(n))
	}
	if f == 0 {
		return "0", nil
	}
	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}
	// 'e' with precision -1 gives the shortest round-trip digits and the
	// exponent; ECMAScript's layout rules are then applied to those.
	digits, exp := shortestDigits(f)
	return sign + layout(digits, exp), nil
}

// shortestDigits returns the significant digits of f and the decimal
// exponent n such that f = 0.digits × 10^n, which is the form the
// ECMAScript algorithm is written in.
func shortestDigits(f float64) (string, int) {
	s := strconv.FormatFloat(f, 'e', -1, 64) // d.ddde±xx
	mant, expPart, _ := strings.Cut(s, "e")
	e, _ := strconv.Atoi(expPart)
	return strings.Replace(mant, ".", "", 1), e + 1
}

// layout applies ECMAScript Number::toString steps 6-10 to k significant
// digits with decimal exponent n.
func layout(digits string, n int) string {
	k := len(digits)
	switch {
	case k <= n && n <= 21:
		return digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		return digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		return "0." + strings.Repeat("0", -n) + digits
	}
	exp := n - 1
	sign := "+"
	if exp < 0 {
		sign, exp = "-", -exp
	}
	mant := digits[:1]
	if k > 1 {
		mant += "." + digits[1:]
	}
	return mant + "e" + sign + strconv.Itoa(exp)
}
