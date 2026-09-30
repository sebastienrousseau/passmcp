// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestStatelessMirrorsXMCPHeaderArguments(t *testing.T) {
	d := &Stateless{}
	d.RememberTools(map[string]json.RawMessage{"q": json.RawMessage(`{"type":"object","properties":{
		"region":{"type":"string","x-mcp-header":"Region"},
		"count":{"type":"integer","x-mcp-header":"Count"},
		"ratio":{"type":"number","x-mcp-header":"Ratio"},
		"bad":{"type":"string","x-mcp-header":"has space"},
		"city":{"type":"string","x-mcp-header":"City"},
		"opts":{"type":"object","properties":{"dry":{"type":"boolean","x-mcp-header":"Dry"}}},
		"list":{"type":"array","x-mcp-header":"List"}}}`)})
	rpc := &Request{Method: "tools/call", Params: json.RawMessage(`{"name":"q","arguments":{
		"region":"eu","count":3,"ratio":0.5,"bad":"x","city":"Zürich","opts":{"dry":false},"list":[1]}}`)}
	h := http.Header{}
	if err := d.PrepareHeaders(h, rpc); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"Region": "eu", "Count": "3", "Dry": "false", "City": EncodeHeaderValue("Zürich")}
	for name, v := range want {
		if got := h.Get(HeaderParamPrefix + name); got != v {
			t.Errorf("%s%s = %q, want %q", HeaderParamPrefix, name, got, v)
		}
	}
	for _, name := range []string{"Ratio", "has space", "List"} {
		if h.Get(HeaderParamPrefix+name) != "" {
			t.Errorf("%s%s must not be mirrored", HeaderParamPrefix, name)
		}
	}
	if v, ok := DecodeHeaderValue(h.Get(HeaderParamPrefix + "City")); !ok || v != "Zürich" {
		t.Errorf("City does not round-trip: %q", v)
	}

	// A tool that was never listed has no schema, so nothing is mirrored.
	h = http.Header{}
	other := &Request{Method: "tools/call", Params: json.RawMessage(`{"name":"unlisted","arguments":{"region":"eu"}}`)}
	if err := d.PrepareHeaders(h, other); err != nil || h.Get(HeaderParamPrefix+"Region") != "" {
		t.Errorf("an unlisted tool got headers: %v %v", h, err)
	}
}
