// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package termsafe

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestStringRemovesControlSequences(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"clean text is untouched":           {"read_file — reads a file", "read_file — reads a file"},
		"newline and tab survive":           {"a\n\tb", "a\n\tb"},
		"SGR colour":                        {"\x1b[31mred\x1b[0m", "red"},
		"cursor movement":                   {"ok\x1b[2A\x1b[Koverwritten", "okoverwritten"},
		"private mode CSI":                  {"\x1b[?1049hx", "x"},
		"window title OSC, BEL":             {"\x1b]0;pwned\x07name", "name"},
		"hyperlink OSC, ST":                 {"\x1b]8;;https://evil\x1b\\link\x1b]8;;\x1b\\", "link"},
		"clipboard OSC 52":                  {"\x1b]52;c;ZXZpbA==\x07tool", "tool"},
		"DCS string":                        {"\x1bPq#0;2;0;0;0\x1b\\after", "after"},
		"APC string":                        {"\x1b_payload\x1b\\after", "after"},
		"two-byte ESC":                      {"\x1bcreset", "reset"},
		"ESC with intermediate":             {"\x1b(Bascii", "ascii"},
		"carriage return":                   {"safe\rDANGER", "safeDANGER"},
		"backspace, bell, DEL":              {"a\bb\x07c\x7fd", "abcd"},
		"C1 CSI in UTF-8":                   {"x\u009b31my", "xy"},
		"C1 OSC in UTF-8":                   {"\u009d0;t\x07z", "z"},
		"other C1 dropped":                  {"a\u0085b", "ab"},
		"Latin-1 supplement kept":           {"café ©", "café ©"},
		"unterminated OSC stops at newline": {"\x1b]0;never ends\nnext line", "\nnext line"},
		"malformed CSI keeps text":          {"\x1b[12;é", "é"},
		"trailing ESC":                      {"end\x1b", "end"},
		"trailing C2 dropped":               {"end\xc2", "end"},
		"C2 before ASCII dropped":           {"\xc2A", "A"},
		// Removing the sequence between them must not join a stray lead
		// byte and a stray continuation byte into U+009B, which is CSI.
		"no C1 formed by removal":   {"\xc2\x1b[0m\x9b2J", "\x9b2J"},
		"ESC ESC":                   {"\x1b\x1b[1mx", "x"},
		"ESC inside string ignored": {"\x1b]0;a\x1bb\x07c", "c"},
	}
	for name, tc := range cases {
		if got := String(tc.in); got != tc.want {
			t.Errorf("%s: String(%q) = %q, want %q", name, tc.in, got, tc.want)
		}
	}
}

// TestWriterHandlesSequencesSplitAcrossWrites is the reason the writer
// keeps state: fmt writes a line in pieces, and a sequence that straddles
// two of them must not get through half-parsed.
func TestWriterHandlesSequencesSplitAcrossWrites(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	for _, part := range []string{"a\x1b", "]0;title", "\x07b\xc2", "\x9b2Jc\xc2", "\xa9"} {
		n, err := w.Write([]byte(part))
		if err != nil || n != len(part) {
			t.Fatalf("Write(%q) = %d, %v", part, n, err)
		}
	}
	if got := buf.String(); got != "abc©" {
		t.Errorf("written %q", got)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func TestWriterReportsTheUnderlyingError(t *testing.T) {
	if _, err := NewWriter(failWriter{}).Write([]byte("x")); err == nil {
		t.Error("error swallowed")
	}
	// Nothing to write is not a write.
	if n, err := NewWriter(failWriter{}).Write([]byte("\x1b[0m")); err != nil || n != 4 {
		t.Errorf("empty clean write = %d, %v", n, err)
	}
}

type inner struct {
	Name   string
	hidden string
}

type doc struct {
	Title   string
	Tags    []string
	Inner   inner
	Ptr     *inner
	Any     any
	ByName  map[string]inner
	Fixed   [2]string
	Raw     []byte
	Count   int
	NilPtr  *inner
	NilAny  any
	NilMap  map[string]string
	private string
}

func TestValueCleansEveryReachableString(t *testing.T) {
	esc := "\x1b[2J"
	in := doc{
		Title:   "t" + esc,
		Tags:    []string{"ok", "x" + esc},
		Inner:   inner{Name: "n" + esc, hidden: esc},
		Ptr:     &inner{Name: "p" + esc},
		Any:     "a" + esc,
		ByName:  map[string]inner{"k" + esc: {Name: "v" + esc}},
		Fixed:   [2]string{"f" + esc, "g"},
		Raw:     []byte(esc),
		Count:   3,
		private: esc,
	}
	got := Value(in)
	for name, s := range map[string]string{
		"Title": got.Title, "Tags[1]": got.Tags[1], "Inner.Name": got.Inner.Name,
		"Ptr.Name": got.Ptr.Name, "Any": got.Any.(string), "Fixed[0]": got.Fixed[0],
		"ByName[k].Name": got.ByName["k"].Name,
	} {
		if strings.ContainsRune(s, 0x1b) {
			t.Errorf("%s still carries an escape: %q", name, s)
		}
	}
	if _, ok := got.ByName["k"]; !ok {
		t.Errorf("map key not cleaned: %v", got.ByName)
	}
	if got.Count != 3 || got.Inner.hidden != esc || got.private != esc || string(got.Raw) != esc {
		t.Errorf("fields that are not printed text changed: %+v", got)
	}
	// The input is the caller's, and a renderer must not rewrite it.
	if in.Title != "t"+esc || in.Tags[1] != "x"+esc || in.Ptr.Name != "p"+esc || in.Fixed[0] != "f"+esc {
		t.Errorf("Value modified its input: %+v", in)
	}
}

func TestValueReturnsACleanDocumentAsItIs(t *testing.T) {
	p := &inner{Name: "n"}
	in := doc{Title: "t", Ptr: p, ByName: map[string]inner{"k": {Name: "v"}}}
	got := Value(in)
	if got.Ptr != p {
		t.Error("a clean pointer was copied")
	}
	if allocs := testing.AllocsPerRun(10, func() { _ = Value(in) }); allocs > 4 {
		t.Errorf("cleaning a clean document allocated %.0f times", allocs)
	}
	if got := Value[*doc](nil); got != nil {
		t.Error("nil pointer")
	}
}
