// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Command servers runs a demonstration MCP server with one deliberate flaw,
// so that what passmcp catches can be seen without pointing it at anybody's
// real server.
//
//	go run ./examples/servers -list
//	go run ./examples/servers -flaw toxic-pair &
//	passmcp check http://127.0.0.1:7777/mcp
//
// Every flaw, and the check that catches it, is in flaws.go; servers_test.go
// proves each row against passmcp's engine on every CI run.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"
	"time"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, (*http.Server).ListenAndServe); err != nil {
		fmt.Fprintln(os.Stderr, "servers:", err)
		os.Exit(2)
	}
}

// listen runs srv: (*http.Server).ListenAndServe in production, a stub in
// tests.
type listen func(srv *http.Server) error

func run(args []string, out io.Writer, serve listen) error {
	fs := flag.NewFlagSet("servers", flag.ContinueOnError)
	fs.SetOutput(out)
	addr := fs.String("addr", "127.0.0.1:7777", "address to listen on; keep it on loopback")
	name := fs.String("flaw", Baseline, "which flaw to serve (see -list)")
	list := fs.Bool("list", false, "print every flaw and the check that catches it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *list {
		return printList(out)
	}
	if _, ok := lookup(*name); !ok {
		return fmt.Errorf("unknown flaw %q; -list shows them", *name)
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", newServer(*name))
	if _, err := fmt.Fprintf(out, "serving %q at http://%s/mcp\n", *name, *addr); err != nil {
		return err
	}
	err := serve(&http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second})
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func printList(out io.Writer) error {
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	// Writes to a tabwriter are buffered; Flush reports any failure.
	_, _ = fmt.Fprintln(tw, "FLAW\tCHECK\tSTATUS\tWHAT IT DOES")
	for _, f := range Flaws {
		check, status := f.Check, f.Status
		if check == "" {
			check, status = "-", "-"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Name, check, status, f.What)
	}
	_, _ = fmt.Fprintln(tw, "\nEvery server, the baseline included, also warns on:")
	for _, b := range BaselineWarnings {
		_, _ = fmt.Fprintf(tw, "  %s: %s\n", b.Check, b.Why)
	}
	return tw.Flush()
}
