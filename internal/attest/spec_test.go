// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package attest

import (
	"encoding/json"
	"strings"
	"testing"

	"satellion.com/passmcp-reporting/spec"
	"satellion.com/passmcp/diagnostics"
)

// The published schema is generated from these types, and ADR 0011 offers
// it to anyone who wants to verify a statement without passmcp. A schema that
// rejected what passmcp actually writes — or accepted what it never would —
// is the failure worth a test: it would be adopted and then be wrong.

func publishedSchema(t *testing.T) json.RawMessage {
	t.Helper()
	// The schema is published by passmcp-reporting, generated there from the
	// attestation types; this is the same bytes as its committed file.
	b := spec.AttestationSchema
	if len(b) == 0 {
		t.Fatal("the published schema is empty")
	}
	return b
}

func TestAStatementPassmcpWritesSatisfiesThePublishedSchema(t *testing.T) {
	st, err := From(sample())
	if err != nil {
		t.Fatal(err)
	}
	b, err := st.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if errs := diagnostics.Validate(publishedSchema(t), b); len(errs) > 0 {
		t.Fatalf("passmcp's own statement fails its published schema:\n%s", strings.Join(errs, "\n"))
	}
}

func TestThePublishedSchemaRefusesWhatPassmcpNeverWrites(t *testing.T) {
	st, err := From(sample())
	if err != nil {
		t.Fatal(err)
	}
	b, err := st.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	pred := doc["predicate"].(map[string]any)

	for name, mutate := range map[string]func(){
		"a status outside the vocabulary": func() {
			pred["verdicts"].([]any)[0].(map[string]any)["status"] = "passed-probably"
		},
		"another predicate type":    func() { doc["predicateType"] = "https://example.com/other/v1" },
		"no basis for the verdicts": func() { delete(pred, "judgedAgainst") },
	} {
		t.Run(name, func(t *testing.T) {
			saved, _ := json.Marshal(doc)
			mutate()
			bad, _ := json.Marshal(doc)
			if errs := diagnostics.Validate(publishedSchema(t), bad); len(errs) == 0 {
				t.Error("accepted")
			}
			_ = json.Unmarshal(saved, &doc)
			pred = doc["predicate"].(map[string]any)
		})
	}
}
