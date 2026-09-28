// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build ignore

// safe_diagnostics runs the library's read-only diagnostics runner against
// an open server and prints the quality score.
//
//	go run examples/safe_diagnostics.go http://127.0.0.1:7777/mcp
package main

import (
	"context"
	"fmt"
	"os"

	"satellion.com/passmcp"
	"satellion.com/passmcp/diagnostics"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: safe_diagnostics <endpoint>")
		os.Exit(2)
	}
	client, err := passmcp.New(passmcp.Config{Endpoint: os.Args[1]})
	if err != nil {
		fail(err)
	}
	ctx := context.Background()
	if _, err := client.Connect(ctx); err != nil {
		fail(err)
	}
	// Default policy: only tools declaring readOnlyHint are invoked.
	runner := diagnostics.NewRunner(diagnostics.Options{RequestsPerSecond: 2})
	report, err := runner.Run(ctx, client)
	if err != nil {
		fail(err)
	}
	fmt.Printf("score %.1f: %d tools, %d executed, %d ok, %d schema mismatches\n",
		report.QualityScore, report.ToolsDiscovered, report.ToolsExecuted, report.Successful, len(report.SchemaMismatches))
	for _, d := range report.Deductions {
		fmt.Println("  ", d)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
