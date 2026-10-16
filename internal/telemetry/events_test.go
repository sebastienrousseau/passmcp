// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package telemetry

import (
	"fmt"
	"slices"
	"testing"
)

// seqs is the sequence numbers of the retained events, in Events order.
func seqs(rec *Recorder) []int {
	var out []int
	for _, e := range rec.Events() {
		out = append(out, e.Seq)
	}
	return out
}

// span is the run of integers from..to inclusive.
func span(from, to int) []int {
	var out []int
	for i := from; i <= to; i++ {
		out = append(out, i)
	}
	return out
}

// Events are returned oldest first at, and at every point past, the
// retention limit, and the drop count and summary cover the evicted ones.
func TestRecorderKeepsNewestInOrder(t *testing.T) {
	rec := New()
	rec.MaxEvents = 4
	for i := 1; i <= 11; i++ {
		rec.add(Event{Method: "GET", URL: fmt.Sprintf("https://h%d/", i), Status: 200})
		first := max(1, i-3)
		if got := seqs(rec); !slices.Equal(got, span(first, i)) {
			t.Fatalf("after %d events, retained %v, want %v", i, got, span(first, i))
		}
		if got := rec.Dropped(); got != first-1 {
			t.Fatalf("after %d events, dropped %d, want %d", i, got, first-1)
		}
	}
	s := rec.Summary()
	if s.Requests != 11 || s.ByStatus["2xx"] != 11 || len(s.ByHost) != 11 {
		t.Errorf("summary = %+v, want all 11 requests", s)
	}
	if rec.Count() != 11 {
		t.Errorf("Count = %d", rec.Count())
	}
}

// Events returns a copy: changing it does not change the recording.
func TestRecorderEventsIsACopy(t *testing.T) {
	rec := New()
	rec.MaxEvents = 2
	for range 5 {
		rec.add(Event{Method: "GET", URL: "https://x/"})
	}
	evs := rec.Events()
	evs[0].URL = "changed"
	if rec.Events()[0].URL != "https://x/" {
		t.Error("Events shares storage with the recorder")
	}
}

// MaxEvents is an exported field, so it can move between adds. Lowering it
// drops the oldest down to the new limit on the next add; raising it lets
// the recording grow again, still in order.
func TestRecorderMaxEventsCanChange(t *testing.T) {
	rec := New()
	rec.MaxEvents = 5
	for range 7 {
		rec.add(Event{Method: "GET", URL: "https://x/"})
	}
	rec.MaxEvents = 3
	rec.add(Event{Method: "GET", URL: "https://x/"})
	if got := seqs(rec); !slices.Equal(got, span(6, 8)) {
		t.Fatalf("after lowering, retained %v", got)
	}
	if rec.Dropped() != 5 {
		t.Fatalf("dropped %d, want 5", rec.Dropped())
	}
	rec.MaxEvents = 6
	for range 4 {
		rec.add(Event{Method: "GET", URL: "https://x/"})
	}
	if got := seqs(rec); !slices.Equal(got, span(7, 12)) {
		t.Fatalf("after raising, retained %v", got)
	}
	rec.MaxEvents = -1
	rec.add(Event{Method: "GET", URL: "https://x/"})
	if got := seqs(rec); !slices.Equal(got, span(7, 13)) {
		t.Fatalf("after unbounding, retained %v", got)
	}
	if s := rec.Summary(); s.Requests != 13 || rec.Dropped() != 6 {
		t.Errorf("summary %d requests, dropped %d", s.Requests, rec.Dropped())
	}
}

func BenchmarkRecorderAddAtCapacity(b *testing.B) {
	rec := New()
	for range DefaultMaxEvents {
		rec.add(Event{Method: "GET", URL: "https://x/"})
	}
	ev := Event{Method: "GET", URL: "https://x/", Status: 200}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec.add(ev)
	}
}
