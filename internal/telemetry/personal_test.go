// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package telemetry

import (
	"strings"
	"testing"
)

// AC: GDPR-01
func TestPersonalValuesFromAResultAreMaskedEverywhere(t *testing.T) {
	r := &Redactor{}
	body := `{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"customer":{"full_name":"Grace Hopper","Email":"grace@example.com"}},` +
		`"content":[{"type":"text","text":"{\"surname\":\"Hopper-Navy\"}"}]}}`
	r.registerPersonalFromResponse(&RPCInfo{Method: "tools/call"}, []byte(body))

	got := r.String("Grace Hopper wrote to grace@example.com; see also Hopper-Navy")
	for _, pii := range []string{"Grace Hopper", "grace@example.com", "Hopper-Navy"} {
		if strings.Contains(got, pii) {
			t.Errorf("String left %q in %q", pii, got)
		}
	}
	if n := r.Summary().PersonalData["field"]; n != 3 {
		t.Errorf("field count = %d, want 3", n)
	}
}

func TestPersonalValuesAreRegisteredFromEventStreams(t *testing.T) {
	r := &Redactor{}
	sse := "event: message\ndata: {\"result\":{\"structuredContent\":{\"phone\":\"0800 000 111\"}}}\n\ndata: not json\n"
	r.registerPersonalFromResponse(&RPCInfo{Method: "resources/read"}, []byte(sse))
	if got := r.String("call 0800 000 111"); strings.Contains(got, "0800 000 111") {
		t.Errorf("SSE value not masked: %q", got)
	}
}

func TestOnlyResultsRegisterPersonalValues(t *testing.T) {
	r := &Redactor{}
	// A tool's name in tools/list is evidence, not personal data.
	r.registerPersonalFromResponse(&RPCInfo{Method: "tools/list"}, []byte(`{"result":{"tools":[{"name":"search"}]}}`))
	r.registerPersonalFromResponse(nil, []byte(`{"name":"Someone"}`))
	r.registerPersonalFromResponse(&RPCInfo{Method: "tools/call"}, nil)
	// Too short to mask without masking every "UK" in the report.
	r.registerPersonalFromResponse(&RPCInfo{Method: "tools/call"}, []byte(`{"name":"Al","email":"`+Mask+`"}`))
	if got := r.String("search Someone Al"); got != "search Someone Al" {
		t.Errorf("String = %q, want it unchanged", got)
	}
	var nilR *Redactor
	nilR.registerPersonalFromResponse(&RPCInfo{Method: "tools/call"}, []byte(`{"name":"Someone"}`))
	if nilR.Text("x") != "x" || nilR.Summary().Total() != 0 {
		t.Error("a nil redactor is not inert")
	}
}

// AC: GDPR-01
func TestTextMasksEmailAndPhonePatterns(t *testing.T) {
	r := &Redactor{}
	in := "mail a.b+c@mail.example.co.uk or ring +1 (415) 555-0100, (212) 555-0199 or 646-555-0123; build 20260927 id 1234567"
	got := r.Text(in)
	for _, pii := range []string{"a.b+c@mail.example.co.uk", "555-0100", "(212) 555-0199", "646-555-0123"} {
		if strings.Contains(got, pii) {
			t.Errorf("Text left %q in %q", pii, got)
		}
	}
	for _, keep := range []string{"20260927", "1234567"} {
		if !strings.Contains(got, keep) {
			t.Errorf("Text masked the non-phone number %q: %q", keep, got)
		}
	}
	s := r.Summary()
	if s.PersonalData["email"] != 1 || s.PersonalData["phone"] != 3 || s.Total() != 4 {
		t.Errorf("summary = %v", s.PersonalData)
	}
	if r.Text("") != "" {
		t.Error("empty text changed")
	}
}

func TestPersonalWalkIsBounded(t *testing.T) {
	r := &Redactor{}
	deep := strings.Repeat(`{"a":`, personalDepth+3) + `{"email":"deep@example.org"}` + strings.Repeat(`}`, personalDepth+3)
	r.registerPersonalFromResponse(&RPCInfo{Method: "tools/call"}, []byte(deep))
	r.mu.RLock()
	n := len(r.personal)
	r.mu.RUnlock()
	if n != 0 {
		t.Errorf("a value below the depth bound was registered")
	}
	// The same value twice is registered once, longest values first.
	r.addPersonal("Ada")
	r.addPersonal("Ada Lovelace")
	r.addPersonal("Ada")
	if len(r.personal) != 2 || r.personal[0] != "Ada Lovelace" {
		t.Errorf("personal = %q", r.personal)
	}
}

func TestKeepIdentifierPreservesCatalogueNamesWithoutWeakeningSecrets(t *testing.T) {
	var nilR *Redactor
	nilR.KeepIdentifier("agtmls")

	r := &Redactor{}
	r.KeepIdentifier("", "ab", "agtmls-mcp", "agtmls", "agtmls_audit", "noya_parse", "agtmls")
	body := `{"result":{"contents":[{"text":"{\"name\":\"agtmls\",\"tools\":[{\"name\":\"noya_parse\"}],\"customer_name\":\"Ada Lovelace\"}"}]}}`
	r.registerPersonalFromResponse(&RPCInfo{Method: "resources/read"}, []byte(body))

	got := r.String("agtmls-mcp tool agtmls_audit and noya_parse for Ada Lovelace")
	for _, want := range []string{"agtmls-mcp", "agtmls_audit", "noya_parse"} {
		if !strings.Contains(got, want) {
			t.Errorf("catalogue identifier %q was masked: %q", want, got)
		}
	}
	if strings.Contains(got, "Ada Lovelace") {
		t.Errorf("customer name leaked: %q", got)
	}

	// An identifier registered from an earlier phase's resources/read before
	// KeepIdentifier runs is also evicted from personal masking.
	r2 := &Redactor{}
	r2.registerPersonalFromResponse(&RPCInfo{Method: "resources/read"}, []byte(`{"result":{"contents":[{"text":"{\"name\":\"reconcile\",\"customer_name\":\"Grace Hopper\"}"}]}}`))
	r2.KeepIdentifier("reconcile")
	got2 := r2.String("tool reconcile and reconcile_many_to_many for Grace Hopper")
	if !strings.Contains(got2, "reconcile_many_to_many") || strings.Contains(got2, "Grace Hopper") {
		t.Errorf("retroactive KeepIdentifier got %q", got2)
	}

	// An actual credential registered via Add is still masked even if it
	// collides with a kept identifier.
	r.Add("noya_parse")
	if strings.Contains(r.String("token noya_parse"), "noya_parse") {
		t.Error("KeepIdentifier weakened secret masking")
	}
}
