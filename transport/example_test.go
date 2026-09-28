// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport_test

import (
	"encoding/json"
	"fmt"

	"satellion.com/passmcp/transport"
)

// The 2026-07-28 revision mirrors the target name into an Mcp-Name header
// so a gateway can route without parsing the body. RFC 9110 restricts a
// field value to visible ASCII, and a tool name is only SHOULD-constrained
// to that — so a name outside it gets the Base64 sentinel form rather than
// a malformed request.
func ExampleEncodeHeaderValue() {
	for _, name := range []string{"search_docs", "recherche_documents_privés"} {
		onTheWire := transport.EncodeHeaderValue(name)
		decoded, ok := transport.DecodeHeaderValue(onTheWire)
		fmt.Printf("%-26s sentinel=%-5v round-trips=%v\n",
			name, onTheWire != name, ok && decoded == name)
	}
	// Output:
	// search_docs                sentinel=false round-trips=true
	// recherche_documents_privés sentinel=true  round-trips=true
}

// An absent resultType means "complete". Servers on revisions before
// 2026-07-28 do not send one, and reading that as anything other than a
// finished result would fail every server written before July.
func ExampleResultType() {
	for _, raw := range []string{
		`{"content": []}`,
		`{"resultType": "complete", "content": []}`,
		`{"resultType": "input_required", "inputRequest": {}}`,
	} {
		fmt.Println(transport.ResultType(json.RawMessage(raw)))
	}
	// Output:
	// complete
	// complete
	// input_required
}
