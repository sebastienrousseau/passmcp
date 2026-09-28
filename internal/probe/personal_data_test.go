// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/telemetry"
)

// AC: GDPR-03
func TestPersonalDataToolsAreRecordedAsInfo(t *testing.T) {
	s := &Session{Opts: Options{Recorder: &telemetry.Recorder{}}}
	tools := []passmcp.Tool{
		{Name: "lookup", InputSchema: json.RawMessage(`{"type":"object","properties":{"customer":{"type":"object","properties":{"Email_Address":{"type":"string"},"ip_address":{"type":"string"}}}}}`),
			OutputSchema: json.RawMessage(`{"type":"object","properties":{"contacts":{"type":"array","items":{"properties":{"name":{"description":"The contact's name"},"mobile":{}}}},"extra":{"anyOf":[{"properties":{"date_of_birth":{}}}]}}}`)},
		{Name: "repo", InputSchema: json.RawMessage(`{"type":"object","properties":{"name":{"type":"string","description":"The repository"}}}`)},
		{Name: "broken", InputSchema: json.RawMessage(`not json`)},
	}
	got := checkPersonalData(s, tools)
	if len(got) != 1 || got[0].ID != "catalog.personal_data" || got[0].Status != Info {
		t.Fatalf("findings = %+v, want one info finding", got)
	}
	want := []string{"input.customer.Email_Address", "output.contacts[].mobile", "output.contacts[].name", "output.extra.date_of_birth"}
	if len(s.PersonalData) != 1 || s.PersonalData[0].Tool != "lookup" || !slices.Equal(s.PersonalData[0].Fields, want) {
		t.Fatalf("PersonalData = %+v, want lookup with %v", s.PersonalData, want)
	}
	if !strings.HasPrefix(got[0].Detail, "lookup: input.customer.Email_Address") {
		t.Errorf("detail = %q", got[0].Detail)
	}

	none := checkPersonalData(s, tools[1:])
	if len(none) != 1 || none[0].Status != Info || !strings.Contains(none[0].Detail, "no tool") || s.PersonalData != nil {
		t.Errorf("no personal data: %+v, %+v", none, s.PersonalData)
	}
}

func TestPersonalSchemaWalkIsBounded(t *testing.T) {
	deep := `{"properties":{"email":{}}}`
	for range personalSchemaDepth + 2 {
		deep = `{"properties":{"a":` + deep + `}}`
	}
	if got := schemaPersonalFields("input", json.RawMessage(deep)); len(got) != 0 {
		t.Errorf("a field below the depth bound was found: %v", got)
	}
	if got := schemaPersonalFields("input", nil); got != nil {
		t.Errorf("empty schema: %v", got)
	}
}
