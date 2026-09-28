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
