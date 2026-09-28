// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package discover

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"satellion.com/passmcp/internal/telemetry"
	"satellion.com/passmcp/transport"
)

// maxBody bounds what is read from any response. Discovery only needs a
// handshake result or a small document, and everything a target returns is
// untrusted.
const maxBody = 1 << 20

// prober makes discovery's requests: through the scope, through the
// recorder, at the run's pace.
type prober struct {
	client *http.Client
	rec    *telemetry.Recorder
	pace   *limiter
	paths  []string
	ua     string
	scope  *scope
	next   atomic.Int64
}

// newProber builds the prober for a run.
func newProber(opts Options, sc *scope) *prober {
	base := opts.Base
	if base == nil {
		base = http.DefaultTransport
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = "passmcp-discover"
	}
	// The scope sits outside the recorder, so a refused request is never
	// sent and never appears in the telemetry as if it had been.
	client := &http.Client{
		Transport:     &scopedTransport{scope: sc, base: opts.Recorder.Wrap(base)},
		CheckRedirect: sc.checkRedirect,
		Timeout:       timeout,
	}
	return &prober{client: client, rec: opts.Recorder, pace: newLimiter(opts.RPS), paths: opts.Paths, ua: ua, scope: sc}
}

// target probes one target and returns the endpoints it proved and the
// URLs that demanded credentials.
func (p *prober) target(ctx context.Context, t Target) ([]Endpoint, []Protected) {
	base, err := url.Parse(t.URL)
	if err != nil || base.Host == "" {
		return nil, nil
	}
	queue := p.candidates(base)
	seen := map[string]bool{}
	var eps []Endpoint
	var prot []Protected
	for len(queue) > 0 {
		c := queue[0]
		queue = queue[1:]
		if seen[c] {
			continue
		}
		seen[c] = true
		if isDocument(c) {
			queue = append(queue, p.card(ctx, c)...)
			continue
		}
		ep, pr := p.handshake(ctx, c)
		if ep != nil {
			eps = append(eps, *ep)
		}
		if pr != nil {
			prot = append(prot, *pr)
		}
	}
	return eps, prot
}

// candidates is the URLs to try on a target: its own path when it named
// one, then every configured path on its origin.
func (p *prober) candidates(base *url.URL) []string {
	origin := base.Scheme + "://" + base.Host
	var out []string
	if base.Path != "" && base.Path != "/" {
		out = append(out, origin+base.Path)
	}
	for _, path := range p.paths {
		out = append(out, origin+"/"+strings.TrimPrefix(path, "/"))
	}
	return out
}

// isDocument reports whether a candidate is a /.well-known document rather
// than an endpoint.
func isDocument(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && strings.HasPrefix(u.Path, "/.well-known/")
}

// card reads a well-known document and returns the same-host endpoint URLs
// it names. A document is a pointer, never proof: each URL it yields must
// still complete a handshake. URLs on other hosts are dropped unread, and
// counted as blocked, because nobody named those hosts.
func (p *prober) card(ctx context.Context, raw string) []string {
	resp, _, err := p.do(ctx, http.MethodGet, raw, nil, nil, "server card")
	if err != nil || resp.status != http.StatusOK {
		return nil
	}
	var doc any
	if json.Unmarshal(resp.body, &doc) != nil {
		return nil
	}
	origin, _ := url.Parse(raw)
	var out []string
	for _, s := range urlsIn(doc) {
		u, err := origin.Parse(s)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
			continue
		}
		if !p.scope.allows(u) {
			continue
		}
		u.Fragment = ""
		out = append(out, u.String())
	}
	return out
}

// urlsIn collects the values of url-like keys anywhere in a JSON document.
func urlsIn(doc any) []string {
	var out []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, val := range x {
				if s, ok := val.(string); ok && isURLKey(k) {
					out = append(out, s)
					continue
				}
				walk(val)
			}
		case []any:
			for _, val := range x {
				walk(val)
			}
		}
	}
	walk(doc)
	return out
}

// isURLKey reports whether a JSON key conventionally holds an endpoint URL.
func isURLKey(k string) bool {
	switch strings.ToLower(k) {
	case "url", "endpoint", "uri", "fixedurl", "serverurl", "server_url":
		return true
	}
	return false
}

// handshake tries to prove raw is an MCP endpoint: first the session-era
// initialize, then the stateless revision's server/discover.
func (p *prober) handshake(ctx context.Context, raw string) (*Endpoint, *Protected) {
	init := map[string]any{
		"protocolVersion": transport.V20251125,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "passmcp-discover", "version": "1"},
	}
	resp, seq, err := p.rpc(ctx, raw, "initialize", init, nil, "initialize")
	if err != nil {
		return nil, nil
	}
	if resp.status == http.StatusUnauthorized {
		return nil, &Protected{URL: raw, Proof: seq, Metadata: resourceMetadata(resp.header)}
	}
	if res, ok := resultOf(resp); ok && isHandshake(res) {
		ep := &Endpoint{URL: raw, Method: "initialize", Proof: seq}
		fillServer(ep, res)
		p.exposure(ctx, ep, sessionHeaders(resp.header, ep.Protocol))
		return ep, nil
	}
	return p.statelessDiscover(ctx, raw)
}

// statelessDiscover tries server/discover, the 2026-07-28 revision's
// optional description call.
func (p *prober) statelessDiscover(ctx context.Context, raw string) (*Endpoint, *Protected) {
	resp, seq, err := p.rpc(ctx, raw, "server/discover", map[string]any{}, stateless(), "server/discover")
	if err != nil {
		return nil, nil
	}
	if resp.status == http.StatusUnauthorized {
		return nil, &Protected{URL: raw, Proof: seq, Metadata: resourceMetadata(resp.header)}
	}
	res, ok := resultOf(resp)
	if !ok {
		return nil, nil
	}
	var d struct {
		SupportedVersions []string                   `json:"supportedVersions"`
		ServerInfo        *serverInfo                `json:"serverInfo"`
		Meta              map[string]json.RawMessage `json:"_meta"`
	}
	if json.Unmarshal(res, &d) != nil || (len(d.SupportedVersions) == 0 && d.ServerInfo == nil && d.Meta == nil) {
		return nil, nil
	}
	ep := &Endpoint{URL: raw, Method: "server/discover", Proof: seq, Protocol: transport.V20260728}
	info := d.ServerInfo
	if info == nil {
		if m, ok := d.Meta[transport.MetaServerInfo]; ok {
			info = &serverInfo{}
			_ = json.Unmarshal(m, info)
		}
	}
	if info != nil {
		ep.Server, ep.Version = bound(info.Name), bound(info.Version)
	}
	p.exposure(ctx, ep, stateless())
	return ep, nil
}

// exposure lists the endpoint's tools with no credentials. An endpoint that
// answers has shown an unauthenticated client its catalogue, which is the
// finding; the request that showed it is kept as the proof. No tool is ever
// called.
func (p *prober) exposure(ctx context.Context, ep *Endpoint, h *rpcHeaders) {
	if h != nil && h.session != "" {
		_, _, _ = p.rpc(ctx, ep.URL, "notifications/initialized", nil, h, "notifications/initialized")
	}
	resp, seq, err := p.rpc(ctx, ep.URL, "tools/list", map[string]any{}, h, "tools/list")
	if err != nil {
		return
	}
	res, ok := resultOf(resp)
	if !ok {
		return
	}
	var list struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if json.Unmarshal(res, &list) != nil || list.Tools == nil {
		return
	}
	ep.Exposed, ep.ExposedProof, ep.Tools = true, seq, len(list.Tools)
}

// rpcHeaders carries what binds a request to its protocol era.
type rpcHeaders struct {
	session   string
	protocol  string
	stateless *transport.Stateless
}

// sessionHeaders is the binding a session-era server asked for.
func sessionHeaders(h http.Header, protocol string) *rpcHeaders {
	if protocol == "" {
		protocol = transport.V20251125
	}
	return &rpcHeaders{session: h.Get(transport.HeaderSessionID), protocol: protocol}
}

// stateless is the 2026-07-28 binding.
func stateless() *rpcHeaders {
	return &rpcHeaders{stateless: &transport.Stateless{
		ProtocolVersion: transport.V20260728,
		ClientInfo:      transport.Implementation{Name: "passmcp-discover", Version: "1"},
	}}
}

// response is what came back, bounded.
type response struct {
	status int
	header http.Header
	body   []byte
}

// rpc sends one JSON-RPC request and returns the response with its req#N.
// A notification carries no id.
func (p *prober) rpc(ctx context.Context, raw, method string, params any, h *rpcHeaders, label string) (*response, int, error) {
	req := &transport.Request{JSONRPC: "2.0", Method: method}
	if !strings.HasPrefix(method, "notifications/") {
		id := p.next.Add(1)
		req.ID = &id
	}
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return nil, 0, err
		}
		req.Params = b
	}
	hdr := http.Header{}
	hdr.Set("Content-Type", "application/json")
	hdr.Set("Accept", "application/json, text/event-stream")
	if h != nil {
		if err := h.apply(hdr, req); err != nil {
			return nil, 0, err
		}
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, 0, err
	}
	return p.do(ctx, http.MethodPost, raw, bytes.NewReader(body), hdr, label)
}

// apply sets the era's headers, and for the stateless revision its _meta.
func (h *rpcHeaders) apply(hdr http.Header, req *transport.Request) error {
	if h.stateless != nil {
		if err := h.stateless.PrepareBody(req); err != nil {
			return err
		}
		return h.stateless.PrepareHeaders(hdr, req)
	}
	if h.protocol != "" {
		hdr.Set(transport.HeaderProtocolVersion, h.protocol)
	}
	if h.session != "" {
		hdr.Set(transport.HeaderSessionID, h.session)
	}
	return nil
}

// do sends one request at the run's pace and finds its req#N.
func (p *prober) do(ctx context.Context, method, raw string, body io.Reader, hdr http.Header, label string) (*response, int, error) {
	if err := p.pace.wait(ctx); err != nil {
		return nil, 0, err
	}
	tag := fmt.Sprintf("%s %s #%d", label, raw, p.next.Add(1))
	req, err := http.NewRequestWithContext(telemetry.WithPhase(ctx, "discovery", tag), method, raw, body)
	if err != nil {
		return nil, 0, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	req.Header.Set("User-Agent", p.ua)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, p.seqOf(tag), err
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	// The recorder files a request when its body is finished with, so the
	// req#N is only known after the close.
	_ = resp.Body.Close()
	seq := p.seqOf(tag)
	if err != nil {
		return nil, seq, err
	}
	return &response{status: resp.StatusCode, header: resp.Header, body: b}, seq, nil
}

// seqOf finds the req#N the recorder gave the request labelled tag. Labels
// are unique per run, so concurrent targets never claim each other's
// requests.
func (p *prober) seqOf(tag string) int {
	evs := p.rec.Events()
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Label == tag {
			return evs[i].Seq
		}
	}
	return 0
}

// resultOf extracts a JSON-RPC result from a 2xx response, whether it came
// as JSON or as the first message of an event stream.
func resultOf(r *response) (json.RawMessage, bool) {
	if r == nil || r.status < 200 || r.status > 299 {
		return nil, false
	}
	payload := r.body
	if strings.HasPrefix(strings.ToLower(r.header.Get("Content-Type")), "text/event-stream") {
		payload = firstEvent(r.body)
	}
	var msg struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if json.Unmarshal(payload, &msg) != nil || len(msg.Result) == 0 || string(msg.Result) == "null" {
		return nil, false
	}
	return msg.Result, true
}

// firstEvent returns the data of the first event in an SSE body.
func firstEvent(b []byte) []byte {
	var data []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), maxBody)
	for sc.Scan() {
		line := sc.Text()
		if line == "" && len(data) > 0 {
			break
		}
		if v, ok := strings.CutPrefix(line, "data:"); ok {
			data = append(data, strings.TrimPrefix(v, " "))
		}
	}
	return []byte(strings.Join(data, "\n"))
}

// serverInfo is the implementation a server names.
type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// isHandshake reports whether an initialize result is really one.
func isHandshake(res json.RawMessage) bool {
	var r struct {
		ProtocolVersion string      `json:"protocolVersion"`
		ServerInfo      *serverInfo `json:"serverInfo"`
	}
	return json.Unmarshal(res, &r) == nil && (r.ProtocolVersion != "" || r.ServerInfo != nil)
}

// fillServer copies what an initialize result said about the server.
func fillServer(ep *Endpoint, res json.RawMessage) {
	var r struct {
		ProtocolVersion string      `json:"protocolVersion"`
		ServerInfo      *serverInfo `json:"serverInfo"`
	}
	_ = json.Unmarshal(res, &r)
	ep.Protocol = bound(r.ProtocolVersion)
	if r.ServerInfo != nil {
		ep.Server, ep.Version = bound(r.ServerInfo.Name), bound(r.ServerInfo.Version)
	}
}

// resourceMetadata extracts the resource_metadata URL a 401 advertises.
func resourceMetadata(h http.Header) string {
	for _, v := range h.Values("WWW-Authenticate") {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if i := strings.Index(part, "resource_metadata="); i >= 0 {
				return bound(strings.Trim(part[i+len("resource_metadata="):], `"`))
			}
		}
	}
	return ""
}

// bound caps server-chosen text before it enters a report.
func bound(s string) string {
	const max = 200
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// limiter spaces requests across the whole run. Zero or less disables it.
type limiter struct {
	mu    sync.Mutex
	every time.Duration
	next  time.Time
}

// newLimiter returns a limiter for rps requests per second.
func newLimiter(rps float64) *limiter {
	if rps <= 0 {
		return &limiter{}
	}
	return &limiter{every: time.Duration(float64(time.Second) / rps)}
}

// wait blocks until the next request may go.
func (l *limiter) wait(ctx context.Context) error {
	if l.every == 0 {
		return ctx.Err()
	}
	l.mu.Lock()
	now := time.Now()
	at := l.next
	if at.Before(now) {
		at = now
	}
	l.next = at.Add(l.every)
	l.mu.Unlock()
	if d := time.Until(at); d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-t.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return ctx.Err()
}
