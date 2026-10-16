// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import (
	"bytes"
	"math/rand/v2"
	"strings"
	"testing"
)

// blankLine must agree with the string test it replaced, Unicode spaces
// and invalid UTF-8 included.
func TestBlankLineMatchesStrings(t *testing.T) {
	for _, in := range []string{"", " ", " \t\r\n", "\u00a0\u2028\u3000", "\u00a0x", "\xff", " \xc2", "{}", "\x85"} {
		if got, want := blankLine([]byte(in)), len(strings.TrimSpace(in)) == 0; got != want {
			t.Errorf("blankLine(%q) = %t, want %t", in, got, want)
		}
	}
}

// sseStream is 200 notifications of about 4 KiB, each split over two data
// lines, followed by the response to id 9.
func sseStream() string {
	var b strings.Builder
	chunk := strings.Repeat("y", 2000)
	for i := 0; i < 200; i++ {
		b.WriteString(": keep-alive\nevent: message\n")
		b.WriteString(`data: {"jsonrpc":"2.0","method":"notifications/progress","params":{"a":"` + chunk + "\n")
		b.WriteString(`data: ","b":"` + chunk + `"}}` + "\n\n")
	}
	b.WriteString(`data: {"jsonrpc":"2.0","id":9,"result":{"ok":true}}` + "\n\n")
	return b.String()
}

func BenchmarkReadSSEResponse(b *testing.B) {
	stream := sseStream()
	b.SetBytes(int64(len(stream)))
	for i := 0; i < b.N; i++ {
		if _, err := readSSEResponse(strings.NewReader(stream), 9); err != nil {
			b.Fatal(err)
		}
	}
}

// The ring keeps exactly the last n bytes written, whatever the sizes of
// the writes and wherever they wrap.
func TestRingBufferKeepsTheTail(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 5))
	for _, size := range []int{1, 2, 7, 64} {
		r := newRingBuffer(size)
		var all []byte
		for range 400 {
			p := make([]byte, rng.IntN(2*size+2))
			for i := range p {
				p[i] = byte('a' + rng.IntN(26))
			}
			if n, err := r.Write(p); n != len(p) || err != nil {
				t.Fatalf("Write = %d, %v", n, err)
			}
			all = append(all, p...)
			want := all[max(0, len(all)-size):]
			if got := r.String(); got != string(want) {
				t.Fatalf("size %d after %d bytes: %q, want %q", size, len(all), got, want)
			}
		}
	}
}

func BenchmarkRingBufferWrite(b *testing.B) {
	r := newRingBuffer(64 << 10)
	p := bytes.Repeat([]byte("stderr line from a chatty server\n"), 128)
	b.SetBytes(int64(len(p)))
	for i := 0; i < b.N; i++ {
		_, _ = r.Write(p)
	}
}

// BenchmarkBlankLine tests a 1 MiB message for blankness, as the stdio
// reader does for every line it reads.
func BenchmarkBlankLine(b *testing.B) {
	line := append([]byte(`{"jsonrpc":"2.0","id":1,"result":{"text":"`), bytes.Repeat([]byte("x"), 1<<20)...)
	line = append(line, `"}}`...)
	b.SetBytes(int64(len(line)))
	for i := 0; i < b.N; i++ {
		if blankLine(line) {
			b.Fatal("not blank")
		}
	}
}
