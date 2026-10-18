// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import "github.com/spf13/pflag"

// htmlAssets is --html-assets: link report.css from the HTML report instead
// of inlining it.
var htmlAssets bool

// outputFlags say what a run produces and where it goes.
func outputFlags() *pflag.FlagSet {
	outOnce.Do(func() {
		fs := pflag.NewFlagSet("output", pflag.ContinueOnError)
		fs.BoolVarP(&interactive, "interactive", "i", false, "pick the tools to exercise in an interactive selector before the run")
		fs.StringVar(&output, "output", "text", "output format: text, json, md, ndjson, html, sarif, junit, attestation, ocsf")
		fs.StringVar(&reportDir, "report-dir", "", "write report.{txt,md,json}, telemetry.ndjson and telemetry.har here")
		fs.StringVar(&retain, "retain", "", "with --report-dir, delete passmcp's own report files there older than this (a Go duration, or days as 30d), logging each on stderr")
		fs.BoolVar(&captureBodies, "capture-bodies", false, "record request/response bodies in telemetry (redacted, capped)")
		fs.BoolVar(&withEvents, "events", false, "embed every telemetry event in JSON output")
		fs.BoolVar(&htmlAssets, "html-assets", false, "with --report-dir, write the HTML report's stylesheet there as report.css and link it instead of inlining it, for a page served under a Content-Security-Policy that refuses inline style")
		fs.BoolVar(&withGuidance, "guidance", false, "embed remediation for each finding in JSON output, keyed by check id")
		fs.BoolVarP(&verbose, "verbose", "v", false, "show evidence references and full info findings")
		fs.BoolVar(&noColor, "no-color", false, "disable ANSI colour")
		fs.StringVar(&otlpEndpoint, "otlp-endpoint", "", "export the finished run as OpenTelemetry traces to this OTLP/HTTP collector")
		fs.StringArrayVar(&otlpHeaders, "otlp-header", nil, "extra header on the OTLP export, \"Name: value\" (repeatable)")
		fs.StringVar(&ocsfEndpoint, "ocsf-endpoint", "", "post the failing and warning findings as OCSF events to this endpoint (your SIEM); nothing is sent without it")
		fs.StringArrayVar(&ocsfHeaders, "ocsf-header", nil, "extra header on the OCSF post, \"Name: value\" (repeatable)")
		fs.StringSliceVar(&phasesOnly, "phases", nil, "run only these phases (comma-separated)")
		fs.StringSliceVar(&phasesSkip, "skip-phases", nil, "skip these phases (comma-separated)")
		outSet = fs
	})
	return outSet
}
