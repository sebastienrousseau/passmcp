// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package web

import (
	"context"
	"net/http"
	"strconv"

	"satellion.com/passmcp/internal/engine"
)

// DefaultMaxInflight is how many runs execute at once. Each holds
// connections, goroutines and, for a stdio target, a process until it
// ends, so the ceiling is what bounds the host's work, not MaxRuns, which
// bounds the reports kept afterwards.
const DefaultMaxInflight = 8

// maxRunEvents bounds the events one run keeps for a browser that
// subscribes late. A subscriber already listening still receives every
// event; only the replay is cut short.
const maxRunEvents = 10000

func (s *Server) startRun(w http.ResponseWriter, r *http.Request) {
	spec, ok := s.admit(w, r)
	if !ok {
		return
	}
	id, err := newToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	rn, ok := s.register(id, spec)
	if !ok {
		w.Header().Set("Retry-After", strconv.Itoa(30))
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "this server is already running as many diagnostics as it allows; try again shortly",
		})
		return
	}
	go s.execute(rn)
	writeJSON(w, http.StatusAccepted, map[string]string{"id": id})
}

// register records a new run if there is room for one to execute, and
// evicts the oldest past MaxRuns. An evicted run is cancelled: once it is
// out of the registry nobody can reach it to cancel it, and it would
// otherwise keep working for no one.
func (s *Server) register(id string, spec engine.RunSpec) (*run, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight >= s.opts.MaxInflight {
		return nil, false
	}
	ctx, cancel := context.WithCancel(s.base)
	rn := &run{id: id, spec: spec, ctx: ctx, cancel: cancel, subs: map[chan engine.Event]struct{}{}}
	s.inflight++
	s.runs[id] = rn
	s.order = append(s.order, id)
	for len(s.order) > s.opts.MaxRuns {
		if old := s.runs[s.order[0]]; old != nil {
			old.cancel()
		}
		delete(s.runs, s.order[0])
		s.order = s.order[1:]
	}
	return rn, true
}

// execute runs rn to completion and releases its in-flight slot.
func (s *Server) execute(rn *run) {
	defer func() {
		rn.cancel()
		s.mu.Lock()
		s.inflight--
		s.mu.Unlock()
	}()
	rn.finish(engine.Run(rn.ctx, rn.spec, engine.SinkFunc(rn.publish)))
}
