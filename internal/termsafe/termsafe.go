// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package termsafe neutralises terminal control sequences in text that is
// about to be written to a terminal.
//
// Tool names, descriptions, error text and content are chosen by whoever
// runs the server under test. Written to a terminal verbatim, an escape
// sequence in one of them is an instruction to the terminal rather than
// text: it can move the cursor over lines already printed, retitle the
// window, write to the clipboard or plant a hyperlink. So every renderer
// meant for a person passes server text through here on the way out.
//
// What is removed: ANSI escape sequences (CSI, OSC, DCS, SOS, PM, APC and
// two-character ESC sequences), in both their 7-bit form and the C1 form
// encoded in UTF-8, and every other C0 and C1 control character and DEL.
// Newline and tab survive, because a multi-line description is still
// legitimate text and the renderers lay it out themselves.
//
// The machine renderings (JSON, NDJSON, SARIF, HAR) do not use this: their
// encoders already escape control characters, and a consumer of those is
// owed exactly what the server sent.
package termsafe

import "io"

// state is where the scanner is inside an escape sequence.
type state uint8

const (
	ground state = iota // ordinary text
	escape              // after ESC
	escMid              // after ESC and an intermediate byte (0x20-0x2F)
	csi                 // inside a control sequence, until its final byte
	str                 // inside a control string (OSC, DCS, SOS, PM, APC)
	strEsc              // after ESC inside a control string
	c2                  // after 0xC2, which may start a UTF-8 C1 control
)

// scanner is the state machine shared by String and Writer, so a sequence
// split across two writes is removed as surely as one inside a string.
type scanner struct{ st state }

// feed appends to out what b contributes to the cleaned text.
func (s *scanner) feed(out []byte, b byte) []byte {
	switch s.st {
	case escape:
		s.afterEscape(b)
	case escMid:
		s.afterIntermediate(b)
	case csi:
		return s.inCSI(out, b)
	case str, strEsc:
		return s.inString(out, b)
	case c2:
		return s.afterC2(out, b)
	default:
		return s.ground(out, b)
	}
	return out
}

// ground handles a byte of ordinary text.
func (s *scanner) ground(out []byte, b byte) []byte {
	switch {
	case b == 0x1b:
		s.st = escape
	case b == 0xc2:
		s.st = c2
	case b == '\n' || b == '\t':
		return append(out, b)
	case b < 0x20 || b == 0x7f:
		// Every other C0 control, carriage return included: a bare CR
		// lets a later line overwrite an earlier one on the screen.
	default:
		return append(out, b)
	}
	return out
}

// afterEscape decides what kind of sequence ESC introduced.
func (s *scanner) afterEscape(b byte) {
	switch {
	case b == '[':
		s.st = csi
	case b == ']' || b == 'P' || b == 'X' || b == '^' || b == '_':
		s.st = str
	case b == 0x1b:
		// ESC ESC: the second one starts over.
	case b >= 0x20 && b <= 0x2f:
		s.st = escMid
	default:
		// A final byte ends a two-character sequence.
		s.st = ground
	}
}

// afterIntermediate consumes intermediate bytes until the final one.
func (s *scanner) afterIntermediate(b byte) {
	if b < 0x20 || b > 0x2f {
		s.st = ground
	}
}

// inCSI consumes a control sequence's parameters. A byte that cannot be
// part of one ends it and is handled as ordinary text, so a malformed
// sequence cannot swallow what follows.
func (s *scanner) inCSI(out []byte, b byte) []byte {
	switch {
	case b >= 0x20 && b <= 0x3f:
		return out
	case b >= 0x40 && b <= 0x7e:
		s.st = ground
		return out
	}
	s.st = ground
	return s.ground(out, b)
}

// inString consumes a control string until BEL or the string terminator.
// A newline also ends it: a string nobody terminated must not take the
// rest of the report with it.
func (s *scanner) inString(out []byte, b byte) []byte {
	switch {
	case b == 0x07:
		s.st = ground
	case b == '\n':
		s.st = ground
		return append(out, b)
	case s.st == strEsc && b == '\\':
		s.st = ground
	case b == 0x1b:
		s.st = strEsc
	default:
		s.st = str
	}
	return out
}

// afterC2 handles the byte after 0xC2. U+0080 to U+009F are the C1
// controls; CSI (U+009B) and the string introducers behave as their ESC
// forms do, and the rest are dropped. U+00A0 to U+00BF are ordinary
// characters and pass through.
//
// A 0xC2 followed by anything else is not UTF-8, and it is dropped rather
// than passed on: kept, it could meet a byte left over after a removed
// sequence and form the very C1 control this exists to remove.
func (s *scanner) afterC2(out []byte, b byte) []byte {
	s.st = ground
	switch {
	case b >= 0x80 && b <= 0x9f:
		s.st = c1State(b)
	case b >= 0xa0 && b <= 0xbf:
		return append(out, 0xc2, b)
	default:
		return s.ground(out, b)
	}
	return out
}

// c1State is the state a C1 control leaves the scanner in.
func c1State(b byte) state {
	switch b {
	case 0x9b: // CSI
		return csi
	case 0x90, 0x98, 0x9d, 0x9e, 0x9f: // DCS, SOS, OSC, PM, APC
		return str
	}
	return ground
}

// needs reports whether s contains a byte the scanner would act on. It is
// the fast path: almost every string a server sends is clean, and a
// renderer should not copy it to learn that.
func needs(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if (b < 0x20 && b != '\n' && b != '\t') || b == 0x7f || b == 0xc2 {
			return true
		}
	}
	return false
}

// String returns s with terminal control sequences removed.
func String(s string) string {
	if !needs(s) {
		return s
	}
	var sc scanner
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		out = sc.feed(out, s[i])
	}
	// A string that ends inside a sequence, or on a lone 0xC2, ends
	// there: what was pending is dropped.
	return string(out)
}

// Writer removes terminal control sequences from everything written
// through it. The state carries across writes, so a sequence split
// between two of them is still removed.
type Writer struct {
	w  io.Writer
	sc scanner
}

// NewWriter wraps w.
func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

// Write cleans p and writes the result. It reports len(p) on success, as
// the caller's bytes were all consumed even when fewer were written.
func (w *Writer) Write(p []byte) (int, error) {
	out := make([]byte, 0, len(p))
	for _, b := range p {
		out = w.sc.feed(out, b)
	}
	if len(out) > 0 {
		if _, err := w.w.Write(out); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}
