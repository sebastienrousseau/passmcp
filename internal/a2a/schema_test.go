// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package a2a

import (
	"strings"
	"testing"
)

// TestSigningPayloadMatchesTheSpecificationExample is A2A v1.0 section
// 8.4.1's own example: required fields kept at their defaults, an
// explicitly set optional field kept, an empty repeated field dropped.
//
// AC: A2A-02
func TestSigningPayloadMatchesTheSpecificationExample(t *testing.T) {
	card := map[string]any{
		"name":        "Example Agent",
		"description": "",
		"capabilities": map[string]any{
			"streaming": false, "pushNotifications": false, "extensions": []any{},
		},
		"skills": []any{},
	}
	got, err := SigningPayload(roundTrip(t, card))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"capabilities":{"pushNotifications":false,"streaming":false},"description":"","name":"Example Agent","skills":[]}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestSigningPayloadExcludesSignaturesAndStripsNestedDefaults(t *testing.T) {
	card := validCard("https://a.example", "JSONRPC", "/rpc")
	card["signatures"] = []any{map[string]any{"protected": "x", "signature": "y"}}
	card["securitySchemes"] = map[string]any{}
	card["provider"] = map[string]any{"url": "https://p.example", "organization": "P"}
	card["x-vendor"] = ""
	ifaces := card["supportedInterfaces"].([]any)
	ifaces[0].(map[string]any)["tenant"] = ""
	card["skills"].([]any)[0].(map[string]any)["examples"] = []any{}
	got, err := SigningPayload(roundTrip(t, card))
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	for _, gone := range []string{"signatures", "securitySchemes", "tenant", "examples"} {
		if strings.Contains(s, `"`+gone+`"`) {
			t.Errorf("%s survived default removal: %s", gone, s)
		}
	}
	for _, kept := range []string{`"streaming":false`, `"provider":`, `"x-vendor":""`} {
		if !strings.Contains(s, kept) {
			t.Errorf("%s was dropped: %s", kept, s)
		}
	}
}

func TestValidCardHasNoSchemaErrors(t *testing.T) {
	card := validCard("https://a.example", "JSONRPC", "/rpc")
	card["securitySchemes"] = map[string]any{
		"bearer": map[string]any{"httpAuthSecurityScheme": map[string]any{"scheme": "Bearer"}},
		"oauth": map[string]any{"oauth2SecurityScheme": map[string]any{"flows": map[string]any{
			"clientCredentials": map[string]any{"tokenUrl": "https://auth.example/token", "scopes": map[string]any{"read": "Read"}},
		}}},
	}
	card["securityRequirements"] = []any{map[string]any{"schemes": map[string]any{"bearer": map[string]any{"list": []any{}}}}}
	card["capabilities"].(map[string]any)["extensions"] = []any{map[string]any{"uri": "https://ext", "params": map[string]any{"a": 1}}}
	if errs := ValidateCard(roundTrip(t, card)); len(errs) != 0 {
		t.Errorf("a valid card reported %v", errs)
	}
}

// TestSchemaErrorsNameTheirJSONPath is the heart of A2A-01: every error
// names where it is.
//
// AC: A2A-01
func TestSchemaErrorsNameTheirJSONPath(t *testing.T) {
	card := validCard("https://a.example", "JSONRPC", "/rpc")
	delete(card, "name")
	card["skills"].([]any)[0].(map[string]any)["tags"] = "cooking"
	card["provider"] = map[string]any{"url": "not a url", "organization": "P"}
	card["preferredTransport"] = "JSONRPC" // an A2A 0.3 field
	card["securitySchemes"] = map[string]any{
		"two": map[string]any{
			"apiKeySecurityScheme":   map[string]any{"location": "body", "name": "k"},
			"httpAuthSecurityScheme": map[string]any{"scheme": "Bearer"},
		},
	}
	card["capabilities"].(map[string]any)["streaming"] = "yes"
	errs := ValidateCard(roundTrip(t, card))
	want := []string{
		"$.name: required by AgentCard",
		"$.skills[0].tags: must be an array",
		"$.provider.url: must be an absolute URL",
		"$.preferredTransport: not a field of AgentCard",
		"$.securitySchemes.two: SecurityScheme must set exactly one",
		"$.securitySchemes.two.apiKeySecurityScheme.location: must be one of",
		"$.capabilities.streaming: must be a boolean",
	}
	all := make([]string, len(errs))
	for i, e := range errs {
		all[i] = e.String()
	}
	joined := strings.Join(all, "\n")
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Errorf("missing %q in:\n%s", w, joined)
		}
	}
}

func TestSchemaRejectsWrongShapes(t *testing.T) {
	if errs := ValidateCard([]any{}); len(errs) != 1 || errs[0].Path != "$" {
		t.Errorf("a non-object card: %v", errs)
	}
	card := validCard("https://a.example", "JSONRPC", "/rpc")
	card["capabilities"] = "none"
	card["skills"] = map[string]any{}
	card["securitySchemes"] = []any{}
	card["defaultInputModes"] = []any{1}
	card["signatures"] = []any{map[string]any{"protected": "p", "signature": "s", "header": "h"}}
	card["securityRequirements"] = []any{map[string]any{"schemes": map[string]any{"x": map[string]any{"list": "nope"}}}}
	errs := ValidateCard(roundTrip(t, card))
	joined := ""
	for _, e := range errs {
		joined += e.String() + "\n"
	}
	for _, w := range []string{
		"$.capabilities: must be an object",
		"$.skills: must be an array",
		"$.securitySchemes: must be an object mapping",
		"$.defaultInputModes[0]: must be a string",
		"$.signatures[0].header: must be a JSON object",
		"$.securityRequirements[0].schemes.x.list: must be an array",
	} {
		if !strings.Contains(joined, w) {
			t.Errorf("missing %q in:\n%s", w, joined)
		}
	}
	scopes := validCard("https://a.example", "JSONRPC", "/rpc")
	scopes["securitySchemes"] = map[string]any{"o": map[string]any{"oauth2SecurityScheme": map[string]any{"flows": map[string]any{
		"deviceCode": map[string]any{"deviceAuthorizationUrl": "https://a/d", "tokenUrl": "https://a/t", "scopes": map[string]any{"r": 1}},
	}}}}
	if errs := ValidateCard(roundTrip(t, scopes)); len(errs) != 1 || !strings.Contains(errs[0].String(), "scopes.r: must be a string") {
		t.Errorf("a non-string scope: %v", errs)
	}
}

func TestSchemaErrorsAreBounded(t *testing.T) {
	card := validCard("https://a.example", "JSONRPC", "/rpc")
	for i := range 200 {
		card["x"+strings.Repeat("y", i)] = 1
	}
	if n := len(ValidateCard(roundTrip(t, card))); n != maxSchemaErrors {
		t.Errorf("%d errors reported, want the cap of %d", n, maxSchemaErrors)
	}
	if got := truncate("ééé", 3); got != "é…" {
		t.Errorf("truncate split a rune: %q", got)
	}
}
