// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"satellion.com/passmcp/internal/clientconf"
)

// AC: ATK-04
// TestWrongAudienceTokenTravelsByName. The token reaches the credentials
// from the variable the spec names, is registered as a secret, and never
// crosses JSON; a stdio target refuses it rather than silently not sending
// it.
func TestWrongAudienceTokenTravelsByName(t *testing.T) {
	t.Setenv("PASSMCP_TEST_OTHER_AUD", "token-for-another-resource")
	s := RunSpec{Target: TargetSpec{Endpoint: "https://x/mcp"}}.WithDefaults()
	s.Creds = CredSpec{Mode: "bearer", Token: "t", WrongAudienceTokenEnv: "PASSMCP_TEST_OTHER_AUD"}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	cr, err := s.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	if cr.WrongAudienceToken != "token-for-another-resource" || !slices.Contains(cr.Secrets(), "token-for-another-resource") {
		t.Errorf("token = %q; secrets carry it: %v", cr.WrongAudienceToken, slices.Contains(cr.Secrets(), "token-for-another-resource"))
	}
	if got := s.credentials().WrongAudienceToken; got != "token-for-another-resource" {
		t.Errorf("credentials() = %q", got)
	}

	s.Creds.WrongAudienceToken = "inline-value"
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "inline-value") || strings.Contains(string(b), "token-for-another-resource") {
		t.Error("a token value reached the serialised spec")
	}
	if !strings.Contains(string(b), "PASSMCP_TEST_OTHER_AUD") {
		t.Error("the variable's name was dropped")
	}

	missing := s
	missing.Creds = CredSpec{Mode: "bearer", Token: "t", WrongAudienceTokenEnv: "PASSMCP_TEST_UNSET_AUD"}
	if _, err := missing.Credentials(); err == nil {
		t.Error("an unset variable was accepted")
	}

	stdio := stdioSpec()
	stdio.Creds = CredSpec{WrongAudienceTokenEnv: "PASSMCP_TEST_OTHER_AUD"}
	if err := stdio.validateHTTPOnly(); err == nil || !strings.Contains(err.Error(), "needs an endpoint URL") {
		t.Errorf("stdio accepted a wrong-audience token: %v", err)
	}
	if err := stdio.Validate(); err == nil {
		t.Error("Validate accepted a wrong-audience token for stdio")
	}
}

// AC: ATK-01
// TestClientConfigReachesProbeOptions, and crosses JSON with names only.
func TestClientConfigReachesProbeOptions(t *testing.T) {
	cfg, err := clientconf.Parse("c.json", []byte(`{"mcpServers": {"a": {"command": "srv", "env": {"API_KEY": "the-real-key"}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	s := RunSpec{Target: TargetSpec{Endpoint: "https://x/mcp"}, ClientConfig: cfg}.WithDefaults()
	cr, err := s.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	if s.probeOptions(cr, nil, nil).ClientConfig != cfg {
		t.Error("probeOptions dropped the client configuration")
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "the-real-key") || !strings.Contains(string(b), "API_KEY") {
		t.Errorf("serialised spec: %s", b)
	}
}
