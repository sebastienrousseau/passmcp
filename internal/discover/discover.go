// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package discover finds MCP endpoints among targets the operator names,
// proves each one speaks MCP, and optionally validates it with the ordinary
// read-only check.
//
// Discovery is explicit. It probes only the hosts the operator listed, at a
// short list of well-known paths, and never scans a range, follows a link to
// another host, or guesses a target. That keeps it on the right side of
// ADR 0008: it is an inventory of servers somebody already knows they run,
// not a way of finding other people's. Every endpoint it reports carries the
// request that proved it, as every finding does (ADR 0002).
package discover

import (
	"context"
	"net/http"
	"sort"
	"sync"
	"time"

	"satellion.com/passmcp/internal/telemetry"
)

// DefaultPaths are the paths probed on each target when the operator does
// not choose their own.
//
// /mcp and /sse are where the reference servers and most frameworks mount
// the Streamable HTTP and legacy SSE transports. The two /.well-known
// entries are documents rather than endpoints: /.well-known/mcp is the name
// the discovery work in the MCP community uses, and server-card.json is
// where the draft MCP Server Cards proposal places a server's card. Neither
// is part of a released specification revision yet, so both are only ever
// read for endpoint URLs on the same host, never trusted as proof.
var DefaultPaths = []string{"/mcp", "/sse", "/.well-known/mcp", "/.well-known/mcp/server-card.json"}

// Source is where a target came from.
type Source struct {
	// Type is "targets", "config", "gateway" or "registry".
	Type string `json:"type"`
	// Ref is the file or registry namespace the source names.
	Ref string `json:"ref"`
}

// Target is one thing to probe: a base URL, or an exact endpoint URL.
type Target struct {
	URL    string `json:"url"`
	Source Source `json:"source"`
}

// Status says how an endpoint compares with the previous run.
type Status string

// The statuses.
const (
	// StatusNew is an endpoint seen for the first time.
	StatusNew Status = "new"
	// StatusSeen is an endpoint a previous run also found.
	StatusSeen Status = "seen"
	// StatusDisappeared is an endpoint a previous run found and this one,
	// probing the same host, did not.
	StatusDisappeared Status = "disappeared"
)

// Endpoint is one URL proven to speak MCP.
type Endpoint struct {
	URL string `json:"url"`
	// Sources lists every source that named this endpoint's target.
	Sources []Source `json:"sources"`
	// Method is how MCP was proven: "initialize" or "server/discover".
	Method string `json:"method"`
	// Proof is the req#N of the request whose answer proved it.
	Proof    int    `json:"proof"`
	Protocol string `json:"protocol_version,omitempty"`
	Server   string `json:"server,omitempty"`
	Version  string `json:"server_version,omitempty"`
	// Exposed is true when the endpoint listed its tools to a client that
	// sent no credentials; ExposedProof is that tools/list request.
	Exposed      bool      `json:"exposed_without_auth"`
	ExposedProof int       `json:"exposed_proof,omitempty"`
	Tools        int       `json:"tools,omitempty"`
	Status       Status    `json:"status"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	// Attestation is set when the endpoint was validated.
	Attestation *Validation `json:"validation,omitempty"`
}

// Protected is a URL that answered 401 to an unauthenticated handshake. It
// may well be an MCP server, but nothing proved it, so it is listed apart
// from the endpoints rather than among them.
type Protected struct {
	URL      string `json:"url"`
	Proof    int    `json:"proof"`
	Metadata string `json:"resource_metadata,omitempty"`
}

// Result is everything a discovery run found.
type Result struct {
	Targets     []Target    `json:"targets"`
	Endpoints   []Endpoint  `json:"endpoints"`
	Disappeared []Endpoint  `json:"disappeared,omitempty"`
	Protected   []Protected `json:"protected,omitempty"`
	// Blocked lists hosts the run refused to contact because nobody named
	// them: a redirect or a server card pointed there.
	Blocked []string `json:"blocked_out_of_scope,omitempty"`
	// Requests is how many requests the run made, all in the telemetry.
	Requests int `json:"requests"`
}

// Exposed counts endpoints that answered tools/list with no credentials.
func (r *Result) Exposed() int {
	n := 0
	for _, e := range r.Endpoints {
		if e.Exposed {
			n++
		}
	}
	return n
}

// Options configure a run.
type Options struct {
	Targets []Target
	// Paths are probed on each target; nil means DefaultPaths.
	Paths []string
	// RPS caps requests per second across the whole run; zero or less
	// disables the cap, as it does for passmcp check.
	RPS float64
	// Concurrency is how many targets are probed at once; at least one.
	Concurrency int
	// Timeout bounds each request.
	Timeout time.Duration
	// Recorder receives every request. Required: its sequence numbers are
	// the req#N every endpoint cites.
	Recorder *telemetry.Recorder
	// Base is the transport requests finally go through; nil means
	// http.DefaultTransport. Tests replace it.
	Base http.RoundTripper
	// UserAgent identifies the prober.
	UserAgent string
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Run probes every target and returns what it proved.
func Run(ctx context.Context, opts Options) *Result {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Concurrency < 1 {
		opts.Concurrency = 1
	}
	if opts.Paths == nil {
		opts.Paths = DefaultPaths
	}
	sc := newScope(opts.Targets)
	p := newProber(opts, sc)

	found := map[string]*Endpoint{}
	var protected []Protected
	var mu sync.Mutex
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	for _, t := range opts.Targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t Target) {
			defer wg.Done()
			defer func() { <-sem }()
			eps, prot := p.target(ctx, t)
			mu.Lock()
			defer mu.Unlock()
			mergeFound(found, eps, t.Source, opts.Now())
			protected = append(protected, prot...)
		}(t)
	}
	wg.Wait()

	res := &Result{Targets: opts.Targets, Blocked: sc.Blocked(), Requests: opts.Recorder.Count()}
	for _, e := range found {
		res.Endpoints = append(res.Endpoints, *e)
	}
	sort.Slice(res.Endpoints, func(i, j int) bool { return res.Endpoints[i].URL < res.Endpoints[j].URL })
	res.Protected = dedupeProtected(protected)
	return res
}

// mergeFound adds a target's endpoints to the run's set, merging sources
// when two targets led to the same endpoint.
func mergeFound(found map[string]*Endpoint, eps []Endpoint, src Source, now time.Time) {
	for _, e := range eps {
		if have, ok := found[e.URL]; ok {
			have.Sources = addSource(have.Sources, src)
			continue
		}
		e.Sources = []Source{src}
		e.FirstSeen, e.LastSeen = now, now
		e.Status = StatusNew
		found[e.URL] = &e
	}
}

// addSource appends src unless it is already listed.
func addSource(list []Source, src Source) []Source {
	for _, s := range list {
		if s == src {
			return list
		}
	}
	return append(list, src)
}

// dedupeProtected keeps one entry per URL, sorted.
func dedupeProtected(in []Protected) []Protected {
	seen := map[string]bool{}
	var out []Protected
	for _, p := range in {
		if seen[p.URL] {
			continue
		}
		seen[p.URL] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}
