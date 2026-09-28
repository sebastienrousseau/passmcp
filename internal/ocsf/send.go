// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package ocsf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Sender posts events to the one endpoint the operator named.
//
// It is the same kind of thing as --otlp-endpoint: an exporter pointed at the
// operator's own collector, configured explicitly, and never on by default.
// Nothing in passmcp calls it unless --ocsf-endpoint was given, which is what
// keeps it inside the no-telemetry decision (ADR 0006).
type Sender struct {
	// Endpoint is where the events go. Empty means nothing is sent.
	Endpoint string
	// Headers are added to the request, typically the collector's token.
	Headers map[string]string
	// Client makes the request. Nil means a client with Timeout.
	Client *http.Client
	// Timeout bounds the request when Client is nil. Zero means ten seconds.
	Timeout time.Duration
}

// Send posts events as one JSON array. An empty endpoint sends nothing and
// is not an error; a collector that refuses the events is.
func (s Sender) Send(ctx context.Context, events []Event) error {
	if strings.TrimSpace(s.Endpoint) == "" {
		return nil
	}
	if err := checkEndpoint(s.Endpoint); err != nil {
		return err
	}
	var body bytes.Buffer
	if err := Write(&body, events); err != nil {
		return fmt.Errorf("encoding OCSF events: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Endpoint, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.Headers {
		req.Header.Set(k, v)
	}
	cl := s.Client
	if cl == nil {
		to := s.Timeout
		if to <= 0 {
			to = 10 * time.Second
		}
		cl = &http.Client{Timeout: to}
	}
	// The events go to the endpoint the operator named and nowhere else: a
	// collector that answers with a redirect does not get to forward them.
	c := *cl
	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("the OCSF endpoint redirected; events are sent only to the endpoint named by --ocsf-endpoint")
	}
	cl = &c
	resp, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("sending OCSF events: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("OCSF endpoint returned %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

// checkEndpoint accepts HTTPS anywhere and plain HTTP only to this machine,
// the terms ADR 0006 holds every operator-named destination to: findings
// are redacted, but they still describe the operator's servers, and they do
// not cross a network in the clear.
func checkEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("--ocsf-endpoint %q is not an absolute URL", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
		return fmt.Errorf("--ocsf-endpoint %q is plain HTTP to another machine; use https, or http only to this one", raw)
	default:
		return fmt.Errorf("--ocsf-endpoint %q must be https (or http to this machine)", raw)
	}
}
