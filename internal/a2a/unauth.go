// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package a2a

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/telemetry"
)

// iface is the interface passmcp asks, from the card's supportedInterfaces.
type iface struct {
	url     string
	binding string
	version string
	tenant  string
}

// firstInterface returns the first interface passmcp can speak: JSON-RPC or
// HTTP+JSON. gRPC is not spoken, and A2A v1.0 section 8.3.2 makes the
// first entry the preferred one.
func firstInterface(card map[string]any) (iface, bool) {
	list, _ := card["supportedInterfaces"].([]any)
	for _, raw := range list {
		m, _ := raw.(map[string]any)
		i := iface{}
		i.url, _ = m["url"].(string)
		i.binding, _ = m["protocolBinding"].(string)
		i.version, _ = m["protocolVersion"].(string)
		i.tenant, _ = m["tenant"].(string)
		if i.url != "" && (i.binding == "JSONRPC" || i.binding == "HTTP+JSON") {
			return i, true
		}
	}
	return iface{}, false
}

// declaredSchemes lists the security schemes the card declares for the
// agent or any of its skills.
func declaredSchemes(card map[string]any) []string {
	seen := map[string]bool{}
	if m, ok := card["securitySchemes"].(map[string]any); ok {
		for k := range m {
			seen[k] = true
		}
	}
	addRequirements(seen, card["securityRequirements"])
	skills, _ := card["skills"].([]any)
	for _, sk := range skills {
		if m, ok := sk.(map[string]any); ok {
			addRequirements(seen, m["securityRequirements"])
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, truncate(k, 40))
	}
	sort.Strings(out)
	return out
}

func addRequirements(seen map[string]bool, raw any) {
	reqs, _ := raw.([]any)
	for _, r := range reqs {
		m, _ := r.(map[string]any)
		schemes, _ := m["schemes"].(map[string]any)
		for k := range schemes {
			seen[k] = true
		}
	}
}

// probeOutcome is what the unauthenticated call showed.
type probeOutcome int

const (
	probeUnknown probeOutcome = iota
	probeServed               // answered with data, no credentials sent
	probeRefused              // refused with 401 or 403
)

// checkUnauthenticated is a2a.unauthenticated: an agent must not serve
// requests without credentials unless it means to, and a card that
// declares no authentication must not hide an agent that answers anyone.
//
// Showing that an agent serves requests takes one request to it. passmcp
// makes the least invasive one A2A defines, ListTasks with a page size of
// one: a read that creates, changes and sends nothing, and whose answer
// passmcp does not copy into the report. It never sends a message or
// invokes a skill.
func (s *session) checkUnauthenticated(ctx context.Context) probe.Finding {
	c := s.check("a2a.unauthenticated", "Agent refuses requests without credentials")
	if s.card == nil {
		return c.skip("the Agent Card could not be read, so there is no interface to ask")
	}
	i, ok := firstInterface(s.card)
	if !ok {
		return c.skip("the card declares no JSON-RPC or HTTP+JSON interface, and passmcp does not speak gRPC")
	}
	if err := s.opts.Policy.Validate(ctx, "agent interface", i.url); err != nil {
		return c.skip("the interface the card names is not one passmcp will contact: " + truncate(err.Error(), 200))
	}
	outcome, detail := s.listTasks(ctx, i)
	return unauthVerdict(c, declaredSchemes(s.card), outcome, detail)
}

// unauthVerdict decides the finding from what the card declares and what
// the unauthenticated call showed.
func unauthVerdict(c *check, schemes []string, outcome probeOutcome, detail string) probe.Finding {
	declared := len(schemes) > 0
	switch {
	case outcome == probeServed && !declared:
		return c.fail(probe.Critical,
			"the card declares no authentication and the agent answered ListTasks with no credentials: "+detail,
			"declare a security scheme in securitySchemes and securityRequirements, and refuse requests that do not satisfy it")
	case outcome == probeServed:
		return c.fail(probe.Critical,
			"the card declares "+strings.Join(schemes, ", ")+" but the agent answered ListTasks with no credentials: "+detail,
			"enforce the declared scheme on every method, not only on the ones that change state")
	case outcome == probeRefused && !declared:
		return c.warn("the agent refused a request with no credentials but the card declares no security scheme, so a client cannot tell how to authenticate: "+detail,
			"declare the scheme the agent enforces in securitySchemes and securityRequirements")
	case outcome == probeRefused:
		return c.pass("the card declares " + strings.Join(schemes, ", ") + ", and the agent refused a request with no credentials: " + detail)
	}
	return c.info("whether the agent serves requests without credentials was not shown: " + detail)
}

// listTasks makes the one unauthenticated call and classifies the answer.
func (s *session) listTasks(ctx context.Context, i iface) (probeOutcome, string) {
	ctx = telemetry.WithPhase(ctx, Phase, "ListTasks without credentials")
	req, err := listTasksRequest(ctx, i)
	if err != nil {
		return probeUnknown, "the request could not be built: " + err.Error()
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return probeUnknown, "the request failed: " + truncate(errString(err), 200)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return classify(i.binding, resp.StatusCode, body)
}

func listTasksRequest(ctx context.Context, i iface) (*http.Request, error) {
	var req *http.Request
	var err error
	if i.binding == "HTTP+JSON" {
		u := strings.TrimRight(i.url, "/")
		if i.tenant != "" {
			u += "/" + url.PathEscape(i.tenant)
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, u+"/tasks?pageSize=1", nil)
	} else {
		params := map[string]any{"pageSize": 1}
		if i.tenant != "" {
			params["tenant"] = i.tenant
		}
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "passmcp-a2a-1", "method": "ListTasks", "params": params})
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, i.url, bytes.NewReader(b))
		if req != nil {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if i.version != "" {
		req.Header.Set("A2A-Version", i.version)
	}
	return req, nil
}

// classify reads the answer. Only a success that carries a task list, or a
// JSON-RPC result, counts as served; only 401 and 403 count as refused.
// Anything else (an error, a missing method, a redirect) shows neither.
func classify(binding string, status int, body []byte) (probeOutcome, string) {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return probeRefused, fmt.Sprintf("HTTP %d", status)
	}
	if status < 200 || status > 299 {
		return probeUnknown, fmt.Sprintf("ListTasks answered HTTP %d", status)
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil {
		return probeUnknown, fmt.Sprintf("HTTP %d with a body that is not a JSON object", status)
	}
	if binding == "HTTP+JSON" {
		if _, ok := m["tasks"]; ok {
			return probeServed, fmt.Sprintf("HTTP %d with a task list", status)
		}
		return probeUnknown, fmt.Sprintf("HTTP %d without a task list", status)
	}
	if _, ok := m["result"]; ok {
		return probeServed, fmt.Sprintf("HTTP %d with a JSON-RPC result", status)
	}
	return probeUnknown, fmt.Sprintf("HTTP %d with a JSON-RPC error, not a result", status)
}
