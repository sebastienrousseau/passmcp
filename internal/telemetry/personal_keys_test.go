// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package telemetry

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The recorder masks a value under every key the personal-data check in
// internal/probe flags in a schema. A field the catalog reports as personal
// data must not then travel in the clear in the HAR, the NDJSON or the
// report. These keys were once known to the probe only; "contact.name"
// also needs the probe's normalisation, which strips dots.
func TestPersonalKeysMatchTheCatalogCheck(t *testing.T) {
	keys := []string{
		"patient_name", "customer_name", "person_name", "contact_name", "employee_name",
		"billing_address", "shipping_address", "mailing_address", "street",
		"passport", "nino", "id_number", "national_identifier", "contact.name",
	}
	for _, key := range keys {
		rec := New()
		value := "value under " + key
		sent := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup"}}`)
		result, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"structuredContent": map[string]string{key: value}}})
		if err != nil {
			t.Fatal(err)
		}
		rec.RecordPipe(context.Background(), "server", sent, result, time.Millisecond, nil)
		if got := rec.Redactor.Text("the tool said " + value); strings.Contains(got, value) {
			t.Errorf("a value under %q was not masked: %q", key, got)
		}
	}
}
