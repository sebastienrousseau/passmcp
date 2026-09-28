// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ClientMetadata is the RFC 7591 client metadata used for dynamic
// registration and, when hosted at an HTTPS URL, as a Client ID Metadata
// Document.
type ClientMetadata struct {
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
}

// Registration is the outcome of client registration.
type Registration struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	// Method records how the client ID was obtained: "cimd", "dcr", or
	// "static".
	Method string `json:"-"`
	// Raw holds the full registration response for DCR.
	Raw json.RawMessage `json:"-"`
}

// RegistrationOptions configures Registrar.Register.
type RegistrationOptions struct {
	// ClientMetadataURL is the HTTPS URL of a hosted Client ID Metadata
	// Document. When the server advertises support it becomes the client_id
	// with no registration round-trip.
	ClientMetadataURL string
	// Metadata is sent to the registration endpoint for DCR.
	Metadata ClientMetadata
	// StaticClientID and StaticClientSecret are used when the server
	// supports neither CIMD nor DCR (pre-registered client).
	StaticClientID     string
	StaticClientSecret string
	// InitialAccessToken, if set, is sent as a Bearer token to the
	// registration endpoint (RFC 7591 §3).
	InitialAccessToken string
}

// ErrRegistrationUnsupported is returned when no registration path is
// available for the authorization server.
var ErrRegistrationUnsupported = errors.New("auth: server supports neither client id metadata documents nor dynamic registration and no static client id was configured")

// Registrar obtains a client identity for an authorization server.
type Registrar struct {
	Client *http.Client
	// Policy validates the registration endpoint before the client
	// metadata (and any initial access token) is posted to it.
	Policy URLPolicy
}

func (r *Registrar) httpClient() *http.Client {
	if r.Client == nil {
		return http.DefaultClient
	}
	return r.Client
}

// Register selects the registration path in this order:
//  1. Client ID Metadata Document, when the server advertises support and
//     a metadata URL is configured.
//  2. Statically configured credentials: an operator who was handed a
//     client id chose it deliberately, so it wins over registering anew.
//  3. RFC 7591 dynamic registration, when a registration endpoint exists.
func (r *Registrar) Register(ctx context.Context, md *ServerMetadata, opts RegistrationOptions) (*Registration, error) {
	if md.ClientIDMetadataDocumentSupported && opts.ClientMetadataURL != "" {
		if !strings.HasPrefix(opts.ClientMetadataURL, "https://") {
			return nil, fmt.Errorf("auth: client metadata url must be https: %q", opts.ClientMetadataURL)
		}
		return &Registration{ClientID: opts.ClientMetadataURL, Method: "cimd"}, nil
	}
	if opts.StaticClientID != "" {
		return &Registration{ClientID: opts.StaticClientID, ClientSecret: opts.StaticClientSecret, Method: "static"}, nil
	}
	if md.RegistrationEndpoint != "" {
		if err := r.Policy.Validate(ctx, "registration endpoint", md.RegistrationEndpoint); err != nil {
			return nil, err
		}
		return r.dynamicRegister(ctx, md.RegistrationEndpoint, opts)
	}
	return nil, ErrRegistrationUnsupported
}

func (r *Registrar) dynamicRegister(ctx context.Context, endpoint string, opts RegistrationOptions) (*Registration, error) {
	body, err := json.Marshal(opts.Metadata)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("auth: build registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if opts.InitialAccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+opts.InitialAccessToken)
	}
	resp, err := r.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth: dynamic registration failed: http %d: %s", resp.StatusCode, truncate(raw, 512))
	}
	var reg Registration
	if err := json.Unmarshal(raw, &reg); err != nil {
		return nil, fmt.Errorf("auth: decode registration: %w", err)
	}
	if reg.ClientID == "" {
		return nil, errors.New("auth: registration response missing client_id")
	}
	reg.Method = "dcr"
	reg.Raw = raw
	return &reg, nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
