// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"encoding/json"
	"runtime"
	"sort"

	"satellion.com/passmcp-reporting/attestation"
	"satellion.com/passmcp/internal/telemetry"
)

// Plan records how this spec runs, for a statement that has to be
// repeatable. The spec's JSON already carries names rather than secret
// values; what was given by value is listed so a repeat can ask for it.
//
// Where the output went and what gated it are dropped: they are how the
// operator used the result, not how the server was measured.
//
// The target is masked the way the report masks it: a command-line
// argument or a query parameter is an ordinary place for a key.
func (s RunSpec) Plan(red *telemetry.Redactor) *attestation.Plan {
	c := s
	c.Target.Endpoint = red.URL(c.Target.Endpoint)
	c.Target.Command = red.String(c.Target.Command)
	c.Target.Args = make([]string, len(s.Target.Args))
	for i, a := range s.Target.Args {
		c.Target.Args[i] = red.String(a)
	}
	if len(c.Target.Args) == 0 {
		c.Target.Args = nil
	}
	c.Output = OutputSpec{}
	c.Gate = nil
	c.Version = ""
	// Token-endpoint parameters are tenant selectors as often as they are
	// assertions, and a statement cannot tell which: they are named below,
	// never recorded.
	c.Creds.Params = nil
	raw, err := json.Marshal(c)
	if err != nil {
		// Every field is plain data; a spec that cannot be marshalled
		// carries no plan rather than a broken one.
		return nil
	}
	// Once more over the whole document, for a registered secret the
	// operator put somewhere else, such as a tool argument. A mask that
	// landed on JSON syntax rather than inside a string leaves no plan.
	masked := red.String(string(raw))
	if !json.Valid([]byte(masked)) {
		return nil
	}
	p := &attestation.Plan{
		Spec:        json.RawMessage(masked),
		Credentials: string(s.credentials().Effective()),
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		Kernel:      kernelRelease(),
	}
	if s.Creds.Token != "" {
		p.ByValue = append(p.ByValue, "token")
	}
	if s.Creds.ClientSecret != "" {
		p.ByValue = append(p.ByValue, "client secret")
	}
	if s.Creds.Basic != "" {
		p.ByValue = append(p.ByValue, "basic")
	}
	var named []string
	for k := range s.Creds.Headers {
		named = append(named, "header "+k)
	}
	for k := range s.Creds.Params {
		named = append(named, "param "+k)
	}
	sort.Strings(named)
	p.ByValue = append(p.ByValue, named...)
	return p
}

// SpecFromPlan reads the spec a plan recorded.
func SpecFromPlan(p *attestation.Plan) (RunSpec, error) {
	var s RunSpec
	err := json.Unmarshal(p.Spec, &s)
	return s, err
}
