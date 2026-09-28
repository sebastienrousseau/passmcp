// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package a2a

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCanonicalizeRFC8785Example is the worked example of RFC 8785 section
// 3.2.4: member sorting, number serialisation and string escaping at once.
//
// AC: A2A-02
func TestCanonicalizeRFC8785Example(t *testing.T) {
	in := `{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}`
	want := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

// TestCanonicalizeSortsByUTF16 is RFC 8785 section 3.2.3's sorting
// example: a character above U+FFFF sorts before one in U+E000-U+FFFF,
// which byte order gets wrong.
func TestCanonicalizeSortsByUTF16(t *testing.T) {
	in := `{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}`
	want := "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}"
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

// TestCanonicalNumbers covers the ECMAScript layout rules RFC 8785 adopts,
// including the boundaries between positional and exponential notation and
// values from the RFC's Appendix B.
func TestCanonicalNumbers(t *testing.T) {
	cases := map[string]string{
		"0":                      "0",
		"-0":                     "0",
		"1":                      "1",
		"-1.5":                   "-1.5",
		"4.35":                   "4.35",
		"1e20":                   "100000000000000000000",
		"1e21":                   "1e+21",
		"1e23":                   "1e+23",
		"0.000001":               "0.000001",
		"0.0000001":              "1e-7",
		"5e-324":                 "5e-324",
		"1.7976931348623157e308": "1.7976931348623157e+308",
		"9007199254740992":       "9007199254740992",
		"295147905179352830000":  "295147905179352830000",
		"0.1":                    "0.1",
		"123456789012345680000":  "123456789012345680000",
		"-1.2345e-10":            "-1.2345e-10",
		"333333333.33333329":     "333333333.3333333",
	}
	for in, want := range cases {
		got, err := canonicalNumber(json.Number(in))
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
	if _, err := canonicalNumber(json.Number("1e999")); err == nil {
		t.Error("an infinite number was accepted")
	}
}

func TestCanonicalizeEscapesControlsOnly(t *testing.T) {
	got, err := Canonicalize([]byte(`"a\u0001\b\f\t\r/\u00e9"`))
	if err != nil {
		t.Fatal(err)
	}
	if want := `"a\u0001\b\f\t\r/é"`; string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestCanonicalizeRejectsBadInput(t *testing.T) {
	for _, in := range []string{`{`, `{} {}`, `[1e400]`} {
		if _, err := Canonicalize([]byte(in)); err == nil {
			t.Errorf("%q was canonicalised", in)
		}
	}
	if _, err := canonicalValue(struct{}{}); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("an unsupported Go value was canonicalised: %v", err)
	}
}
