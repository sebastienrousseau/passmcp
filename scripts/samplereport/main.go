// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build ignore

// Command samplereport produces the report published at /sample on the
// site, by running passmcp against a fixture server started beside it.
//
// It exists so the sample is the tool's real output rather than a
// screenshot that drifts. The fixture deliberately has flaws — a thin
// description, a missing outputSchema, a tool that accepts a call with a
// required argument omitted — because a sample with nothing wrong shows a
// reader nothing about what passmcp is for.
//
// Usage: go run ./scripts/samplereport/main.go <passmcp-binary> <out-dir>
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: samplereport <passmcp-binary> <out-dir>")
	}
	bin, outDir := os.Args[1], os.Args[2]

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(handle)}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	endpoint := fmt.Sprintf("http://%s/mcp", ln.Addr().String())
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		log.Fatal(err)
	}

	// The report directory gives the page every rendering at once, so a
	// visitor can read the HTML and download the JSON their pipeline
	// would consume.
	cmd := exec.Command(bin, "check", endpoint,
		"--output", "html",
		"--report-dir", outDir,
		"--rps", "0",
		"--samples", "2",
		"--no-color",
	)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	// A failing finding exits 2, which is the normal outcome here: the
	// fixture has flaws on purpose. Only an inability to produce a report
	// is fatal.
	if len(out) == 0 {
		log.Fatalf("passmcp produced no report: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "index.html"), out, 0o600); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %s (%d bytes)\n", filepath.Join(outDir, "index.html"), len(out))
}

// handle is a small MCP server with realistic shortcomings.
func handle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	id := req.ID
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Mcp-Session-Id", "sample-session")

	switch req.Method {
	case "initialize":
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"acme-crm","version":"2.4.0"},"instructions":"Look up and summarise customer records."}}`, id)
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "tools/list":
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[
			{"name":"find_customer","description":"Find a customer by email address or account number. Returns the account record.","annotations":{"readOnlyHint":true},"inputSchema":{"type":"object","required":["query"],"properties":{"query":{"type":"string","description":"An email address or a 10-digit account number."}}},"outputSchema":{"type":"object","required":["found"],"properties":{"found":{"type":"boolean"}}}},
			{"name":"list_orders","description":"Lists orders.","annotations":{"readOnlyHint":true},"inputSchema":{"type":"object","required":["customer_id"],"properties":{"customer_id":{"type":"string"}}}},
			{"name":"summarise_account","description":"Produce a short written summary of an account, suitable for an agent to relay to a customer.","annotations":{"readOnlyHint":true},"inputSchema":{"type":"object","required":["customer_id"],"properties":{"customer_id":{"type":"string","description":"The account number."}}}}
		]}}`, id)
	case "tools/call":
		// list_orders accepts a call with its required argument missing,
		// which is the finding the sample exists to demonstrate.
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"ok"}],"structuredContent":{"found":true}}}`, id)
	case "ping":
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{}}`, id)
	default:
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"no such method"}}`, id)
	}
}
