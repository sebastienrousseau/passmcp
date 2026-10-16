// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package telemetry

// Events returns a copy of everything recorded so far, oldest first.
func (r *Recorder) Events() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ordered()
}

// ordered copies the retained events, oldest first. The caller holds r.mu.
func (r *Recorder) ordered() []Event {
	out := make([]Event, len(r.events))
	n := copy(out, r.events[r.head:])
	copy(out[n:], r.events[:r.head])
	return out
}

// maxEvents resolves the retention limit. It must be called with r.mu held
// or from a context where concurrent mutation is impossible.
func (r *Recorder) maxEvents() int {
	if r.MaxEvents == 0 {
		return DefaultMaxEvents
	}
	return r.MaxEvents
}

func (r *Recorder) add(e Event) {
	r.mu.Lock()
	r.seq++
	e.Seq = r.seq
	r.retain(e)
	if r.first.IsZero() {
		r.first = e.Time
	}
	if end := e.Time.Add(e.Timings.Total); end.After(r.last) {
		r.last = end
	}
	sink := r.Sink
	r.mu.Unlock()
	if sink != nil {
		sink(e)
	}
}

// retain stores e within MaxEvents. At the limit, e overwrites the oldest
// event in place, so an add costs the same however many are retained;
// shifting the slice down by one, as this once did, copied every retained
// event on every add. Evicted events are folded into the running aggregate
// so the summary still describes the whole run. The caller holds r.mu.
func (r *Recorder) retain(e Event) {
	maxEv := r.maxEvents()
	if maxEv > 0 && len(r.events) == maxEv {
		accumulate(&r.agg, r.events[r.head])
		r.dropped++
		r.events[r.head] = e
		r.head = (r.head + 1) % maxEv
		return
	}
	// Below the limit, above it (MaxEvents was lowered) or unbounded: the
	// slice is put back in order and appended to, as a plain slice.
	if r.head != 0 {
		r.events = r.ordered()
		r.head = 0
	}
	r.events = append(r.events, e)
	if maxEv > 0 && len(r.events) > maxEv {
		drop := len(r.events) - maxEv
		for _, old := range r.events[:drop] {
			accumulate(&r.agg, old)
		}
		r.dropped += drop
		r.events = append(r.events[:0], r.events[drop:]...)
	}
}
