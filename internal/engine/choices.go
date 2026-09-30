// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"satellion.com/passmcp"
	"satellion.com/passmcp/auth"
	"satellion.com/passmcp/diagnostics"
	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/telemetry"
)

// Drawing a selector is a surface's own business: a terminal draws a list
// and a browser draws checkboxes, and neither should have an opinion about
// the other. Deciding what goes in the list is not.
//
// That distinction is the parity contract in miniature. SelectTools already
// lives here, so every surface widens the policy identically once a choice
// is made. What did not was the half before it — connecting, listing the
// catalogue and classifying each tool — which sat in cmd and was therefore
// reachable from exactly one of the three surfaces. `-i` was CLI-and-TUI
// only for no reason other than where the function happened to be defined,
// which is the shape the contract exists to catch.

// ToolChoice is one row of a selector, in the terms every surface needs.
type ToolChoice struct {
	// Name is the tool as the server names it.
	Name string `json:"name"`
	// Kind is read-only, mutating or destructive, from the tool's
	// annotations and the specification's defaults for the ones it omits.
	Kind string `json:"kind"`
	// Policy is whether the current policy would invoke it without being
	// widened: "allowed", or "opt-in" for a tool that needs the choice to
	// be made deliberately.
	Policy string `json:"policy"`
	// Description is the server's own text, shown so a person can tell two
	// similarly named tools apart.
	Description string `json:"description"`
}

// choiceTimeout bounds the selector's own connection. It is not the run's
// timeout: nothing is being diagnosed here, and a server that cannot list
// its tools promptly should say so before somebody is staring at an empty
// list rather than after.
const choiceTimeout = 60 * time.Second

// ListToolChoices connects as the spec describes and lists the catalogue
// with each tool's policy class.
//
// It opens a connection of its own, because the tools have to be listed
// before the run that would have listed them. Over stdio that means a
// second process, briefly, closed before the run starts its own — the
// alternative is holding somebody's server open while they read a list,
// which is the longer-lived mistake.
func ListToolChoices(ctx context.Context, spec RunSpec, version string) ([]ToolChoice, error) {
	spec = spec.WithDefaults()
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	cr, err := spec.Credentials()
	if err != nil {
		return nil, err
	}
	rec := telemetry.New()
	for _, sec := range cr.Secrets() {
		rec.Redactor.Add(sec)
	}

	cfg, err := choiceConfig(spec, cr, rec, version)
	if err != nil {
		return nil, err
	}
	client, err := passmcp.New(cfg)
	if err != nil {
		return nil, err
	}
	defer func() { _ = client.Close() }()

	if err := connectForChoices(ctx, client, spec, cr); err != nil {
		return nil, err
	}
	return toolChoices(ctx, client, spec.ToolPolicy())
}

// ListCatalogue connects as the spec describes and returns the catalogue
// itself, schemas and annotations included.
//
// The same two requests the selector makes, kept separate because what
// they are for differs: a selector wants rows a person can read, and a
// watcher wants everything a reviewer approved. Sharing the connection
// logic and not the shape is what keeps a pulse cheap enough to run on a
// schedule while still being a complete snapshot.
func ListCatalogue(ctx context.Context, spec RunSpec, version string) ([]passmcp.Tool, error) {
	spec = spec.WithDefaults()
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	cr, err := spec.Credentials()
	if err != nil {
		return nil, err
	}
	rec := telemetry.New()
	for _, sec := range cr.Secrets() {
		rec.Redactor.Add(sec)
	}
	cfg, err := choiceConfig(spec, cr, rec, version)
	if err != nil {
		return nil, err
	}
	client, err := passmcp.New(cfg)
	if err != nil {
		return nil, err
	}
	defer func() { _ = client.Close() }()

	if err := connectForChoices(ctx, client, spec, cr); err != nil {
		return nil, err
	}
	return client.ListTools(ctx)
}

// choiceConfig builds the client configuration for the selector's own
// connection, over whichever transport the spec names.
func choiceConfig(spec RunSpec, cr *creds.Credentials, rec *telemetry.Recorder, version string) (passmcp.Config, error) {
	info := passmcp.Implementation{Name: "passmcp", Version: version}
	var cfg passmcp.Config
	if spec.Target.Stdio() {
		cfg = passmcp.Config{
			Stdio: &passmcp.StdioConfig{
				Command: spec.Target.Command, Args: spec.Target.Args,
				Dir: spec.Target.Dir, PassEnv: spec.Target.PassEnv, Env: spec.Target.Env,
			},
			ClientInfo: info,
		}
	} else {
		cfg = passmcp.Config{
			Endpoint:   spec.Target.Endpoint,
			HTTPClient: &http.Client{Timeout: choiceTimeout, Transport: rec.Wrap(auth.URLPolicy{}.EndpointTransport(spec.Target.Endpoint))},
			ClientInfo: info,
		}
	}
	cr.Apply(&cfg)
	return cfg, nil
}

// connectForChoices gets far enough to list tools, by whichever route the
// credentials require.
func connectForChoices(ctx context.Context, client *passmcp.Client, spec RunSpec, cr *creds.Credentials) error {
	if spec.Target.Stdio() {
		_, err := client.Connect(ctx)
		return err
	}
	if cr.Effective() == creds.ModeAuthorizationCode {
		st, err := (&creds.Store{}).Get(spec.Target.Endpoint)
		if err != nil {
			return err
		}
		if st == nil {
			return &LoginRequiredError{Message: fmt.Sprintf("no stored token for %s; run `passmcp login %s`", spec.Target.Endpoint, spec.Target.Endpoint)}
		}
		_, err = client.Resume(ctx, st.Source(creds.HTTP{C: client.HTTPClient()}))
		return err
	}
	res, err := client.Connect(ctx)
	if err != nil {
		return err
	}
	if res.Status != passmcp.StatusConnected {
		return &LoginRequiredError{Message: "server requires a user login; run `passmcp login` first"}
	}
	return nil
}

// LoginRequiredError is returned when a connection needs a user's
// authorization that the operator has not given yet: no stored token, or
// a server that answered with an authorization URL.
//
// A type rather than a string so a caller can tell "sign in first" from a
// server that is down, which is the difference between an operator's
// to-do and an outage (internal/watch counts them apart).
type LoginRequiredError struct {
	// Message says what to do about it.
	Message string
}

func (e *LoginRequiredError) Error() string { return e.Message }

// toolChoices classifies a catalogue for a selector. Shared by both
// transports, so what a selector offers cannot depend on how the server
// was reached.
func toolChoices(ctx context.Context, client *passmcp.Client, policy diagnostics.Policy) ([]ToolChoice, error) {
	tools, err := client.ListTools(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ToolChoice, 0, len(tools))
	for _, t := range tools {
		kind := "mutating"
		switch {
		case t.IsReadOnly():
			kind = "read-only"
		case t.IsDestructive():
			kind = "destructive"
		}
		pol := "opt-in"
		if policy.Decide(t).Execute {
			pol = "allowed"
		}
		out = append(out, ToolChoice{Name: t.Name, Kind: kind, Policy: pol, Description: t.Description})
	}
	return out, nil
}
