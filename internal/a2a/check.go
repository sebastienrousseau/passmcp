// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package a2a

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"satellion.com/passmcp/auth"
	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/telemetry"
)

// WellKnownPath is where an agent publishes its Agent Card (A2A v1.0
// section 8.2): at the root of the server's domain.
const WellKnownPath = "/.well-known/agent-card.json"

// Phase is the phase name A2A findings carry. It is not one of the nine
// MCP phases: an A2A run is its own command, against its own protocol.
const Phase = "a2a"

// maxCardBytes bounds the card passmcp reads. A card is a manifest; one past
// a mebibyte is not one a verifier should be made to hold.
const maxCardBytes = 1 << 20

// Options configures one A2A check.
type Options struct {
	// URL is the agent's base URL, or its Agent Card URL.
	URL string
	// Timeout bounds each request. Zero means 20 seconds.
	Timeout time.Duration
	// Policy decides which URLs named by the card passmcp may fetch: the
	// JWKS a signature points at, and the interface it asks for tasks.
	// The zero value is the strict policy: HTTPS and public hosts only,
	// loopback excepted.
	Policy auth.URLPolicy
	// Transport is the base HTTP transport; nil means a clone of
	// http.DefaultTransport that applies Policy again at connect time. The
	// recorder wraps it either way.
	Transport http.RoundTripper
}

// Result is the outcome of one A2A check.
type Result struct {
	// Target is the agent's base URL.
	Target string `json:"target"`
	// CardURL is where the card was fetched from.
	CardURL string `json:"card_url"`
	// CardDigest is the SHA-256 of the card's JCS canonical form, in hex.
	CardDigest string `json:"card_digest,omitempty"`
	// Signed says whether the card carried a signature, and KeyID which
	// key verified it.
	Signed bool   `json:"signed"`
	KeyID  string `json:"key_id,omitempty"`
	// Agent is what the card said the agent was.
	Agent AgentInfo `json:"agent"`
	// SchemaErrors is every way the card departs from A2A v1.
	SchemaErrors []SchemaError `json:"schema_errors,omitempty"`
	// Findings is every check that ran, in the order it ran.
	Findings []probe.Finding `json:"findings"`
	Started  time.Time       `json:"started"`
	Duration probe.Millis    `json:"duration_ms"`

	// Recorder holds the requests the run made; findings cite them as
	// req#N.
	Recorder *telemetry.Recorder `json:"-"`
}

// AgentInfo is the Agent Card's claim about the agent.
type AgentInfo struct {
	Name            string `json:"name,omitempty"`
	Version         string `json:"version,omitempty"`
	ProtocolVersion string `json:"protocol_version,omitempty"`
}

// Failed reports whether any check failed.
func (r *Result) Failed() bool {
	for _, f := range r.Findings {
		if f.Status == probe.Fail {
			return true
		}
	}
	return false
}

// session is one run's state.
type session struct {
	opts   Options
	rec    *telemetry.Recorder
	client *http.Client
	base   *url.URL
	res    *Result
	// card is the decoded card, nil when it could not be read.
	card  map[string]any
	fetch cardFetch
}

// Run checks the agent at opts.URL. The error is for a URL that cannot be
// checked at all; everything the agent did is a finding.
func Run(ctx context.Context, opts Options) (*Result, error) {
	base, cardURL, err := targetURLs(opts.URL)
	if err != nil {
		return nil, err
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 20 * time.Second
	}
	rt := opts.Transport
	if rt == nil {
		// The policy again at connect time for every host but the agent's
		// own: a JWKS or interface URL from the card must not resolve one
		// way for the check and another for the connection.
		rt = opts.Policy.Transport(nil, base.Hostname())
	}
	rec := telemetry.New()
	s := &session{
		opts: opts,
		rec:  rec,
		client: &http.Client{
			Transport:     rec.Wrap(rt),
			Timeout:       opts.Timeout,
			CheckRedirect: sameHostRedirects,
		},
		base: base,
		res:  &Result{Target: base.String(), CardURL: cardURL, Started: time.Now(), Recorder: rec},
	}
	s.fetch = s.fetchCard(ctx, cardURL)
	s.res.Findings = append(s.res.Findings,
		s.checkTransport(),
		s.checkSchema(),
		s.checkSignature(ctx),
		s.checkUnauthenticated(ctx),
	)
	s.res.Duration = probe.Millis(time.Since(s.res.Started))
	return s.res, nil
}

// targetURLs returns the agent's base URL and its card URL. A URL that
// already names the well-known card is taken as the card; anything else is
// the agent, whose card is at the root of its domain.
func targetURLs(raw string) (*url.URL, string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, "", fmt.Errorf("a2a: %q is not an http(s) URL", raw)
	}
	base := &url.URL{Scheme: u.Scheme, Host: u.Host}
	return base, base.String() + WellKnownPath, nil
}

// sameHostRedirects follows a redirect only on the host the run started
// on. A card that moves to another host is a different card.
func sameHostRedirects(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 || req.URL.Host != via[0].URL.Host {
		return http.ErrUseLastResponse
	}
	return nil
}

// cardFetch is what fetching the card produced.
type cardFetch struct {
	status int
	body   []byte
	err    error
}

func (s *session) fetchCard(ctx context.Context, cardURL string) cardFetch {
	ctx = telemetry.WithPhase(ctx, Phase, "agent card")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cardURL, nil)
	if err != nil {
		return cardFetch{err: err}
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return cardFetch{err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCardBytes+1))
	if err == nil && len(body) > maxCardBytes {
		err = fmt.Errorf("the card is larger than %d bytes", maxCardBytes)
	}
	return cardFetch{status: resp.StatusCode, body: body, err: err}
}

// check is one finding being built, citing the requests made while it
// was open, as probe's checks do.
type check struct {
	s     *session
	f     probe.Finding
	from  int
	start time.Time
}

func (s *session) check(id, title string) *check {
	return &check{s: s, f: probe.Finding{ID: id, Phase: Phase, Title: title}, from: s.rec.Count(), start: time.Now()}
}

func (c *check) done(st probe.Status, sev probe.Severity, detail, advice string) probe.Finding {
	c.f.Status, c.f.Severity, c.f.Detail, c.f.Advice = st, sev, detail, advice
	c.f.DocURL = probe.DocURL(c.f.ID)
	c.f.Duration = probe.Millis(time.Since(c.start))
	if to := c.s.rec.Count(); to > c.from {
		if to-c.from == 1 {
			c.f.Evidence = append(c.f.Evidence, fmt.Sprintf("req#%d", to))
		} else {
			c.f.Evidence = append(c.f.Evidence, fmt.Sprintf("req#%d-%d", c.from+1, to))
		}
	}
	return c.f
}

func (c *check) pass(detail string) probe.Finding { return c.done(probe.Pass, "", detail, "") }
func (c *check) info(detail string) probe.Finding { return c.done(probe.Info, "", detail, "") }
func (c *check) skip(reason string) probe.Finding { return c.done(probe.Skip, "", reason, "") }
func (c *check) warn(detail, advice string) probe.Finding {
	return c.done(probe.Warn, probe.Minor, detail, advice)
}
func (c *check) fail(sev probe.Severity, detail, advice string) probe.Finding {
	return c.done(probe.Fail, sev, detail, advice)
}
func (c *check) ev(items ...string) *check { c.f.Evidence = append(c.f.Evidence, items...); return c }

// cardRequest is the evidence reference for the card fetch, which is the
// first request every run makes.
const cardRequest = "req#1"

// checkTransport is a2a.transport: the card, and so the agent, must not be
// served over plain HTTP from a host other than this machine, as net.scheme
// holds an MCP endpoint to.
func (s *session) checkTransport() probe.Finding {
	c := s.check("a2a.transport", "Agent Card served over HTTPS")
	host := s.base.Hostname()
	switch {
	case s.base.Scheme == "https" && s.fetch.status != 0:
		return c.ev(cardRequest).pass("the Agent Card was served over HTTPS")
	case s.base.Scheme == "https":
		return c.ev(cardRequest).skip("the Agent Card could not be fetched over HTTPS: " + truncate(errString(s.fetch.err), 200))
	case isLoopback(host):
		return c.ev(cardRequest).info("plain http to loopback " + host + " (acceptable for local agents)")
	}
	return c.ev(cardRequest).fail(probe.Critical,
		"the Agent Card is served over plain http from "+host+": the card, and the credentials a client then sends, travel in clear text and can be altered in transit",
		"serve the agent and its card over TLS; A2A requires HTTPS for HTTP-based interfaces in production")
}

// checkSchema is a2a.card_schema: the card must be fetchable at the
// well-known path and be a valid A2A v1 AgentCard.
func (s *session) checkSchema() probe.Finding {
	c := s.check("a2a.card_schema", "Agent Card is a valid A2A v1 card")
	c.ev(cardRequest)
	const advice = "publish an A2A v1 Agent Card at " + WellKnownPath + " on the agent's domain"
	switch {
	case s.fetch.err != nil && s.fetch.status == 0:
		return c.fail(probe.Critical, "the Agent Card could not be fetched from "+s.res.CardURL+": "+truncate(errString(s.fetch.err), 200), advice)
	case s.fetch.status != http.StatusOK:
		return c.fail(probe.Critical, fmt.Sprintf("%s answered HTTP %d, not an Agent Card", s.res.CardURL, s.fetch.status), advice)
	case s.fetch.err != nil:
		return c.fail(probe.Critical, truncate(s.fetch.err.Error(), 200), advice)
	}
	v, err := decode(s.fetch.body)
	card, isObject := v.(map[string]any)
	if err != nil || !isObject {
		return c.fail(probe.Critical, "the response at "+WellKnownPath+" is not a JSON object", advice)
	}
	s.card = card
	s.describeCard()
	errs := ValidateCard(card)
	s.res.SchemaErrors = errs
	if len(errs) > 0 {
		return c.fail(probe.Major, schemaSummary(errs),
			"fix each path named against the AgentCard message in the A2A v1 specification; clients that parse strictly reject the card")
	}
	skills, _ := card["skills"].([]any)
	ifaces, _ := card["supportedInterfaces"].([]any)
	return c.pass(fmt.Sprintf("a valid A2A v1 Agent Card for %q: %d skill(s), %d interface(s)", truncate(s.res.Agent.Name, 80), len(skills), len(ifaces)))
}

// describeCard records what the card says about the agent, and the digest
// of its canonical form.
func (s *session) describeCard() {
	if b, err := canonicalValue(s.card); err == nil {
		sum := sha256.Sum256(b)
		s.res.CardDigest = hex.EncodeToString(sum[:])
	}
	name, _ := s.card["name"].(string)
	version, _ := s.card["version"].(string)
	s.res.Agent = AgentInfo{Name: truncate(name, 200), Version: truncate(version, 80)}
	if iface, ok := firstInterface(s.card); ok {
		s.res.Agent.ProtocolVersion = truncate(iface.version, 20)
	}
}

func schemaSummary(errs []SchemaError) string {
	shown := errs
	if len(shown) > 5 {
		shown = shown[:5]
	}
	parts := make([]string, len(shown))
	for i, e := range shown {
		parts[i] = e.String()
	}
	more := ""
	if len(errs) > len(shown) {
		more = fmt.Sprintf("; and %d more", len(errs)-len(shown))
	}
	return fmt.Sprintf("%d schema error(s): %s%s", len(errs), strings.Join(parts, "; "), more)
}

func isLoopback(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func errString(err error) string {
	if err == nil {
		return "no response"
	}
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return uerr.Err.Error()
	}
	return err.Error()
}
