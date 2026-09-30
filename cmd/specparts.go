// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"strings"
	"time"

	"satellion.com/passmcp/internal/engine"
	"satellion.com/passmcp/internal/policy"
)

// The parts of a run specification buildSpec assembles from the flags.

// loadGate reads the --policy file, when one was named. The file is read
// here, in the surface, and the loaded policy goes into the spec: a path
// in the spec would ask whichever process received it to open a file
// somebody else named.
func loadGate() (*policy.Policy, error) {
	if strings.TrimSpace(policyFile) == "" {
		return nil, nil
	}
	return policy.Load(policyFile)
}

// policySpec is the invocation and discovery policy, from the flags.
func policySpec(overrides map[string]map[string]any) engine.PolicySpec {
	return engine.PolicySpec{
		AllowMutations: allowMutations, AllowDestructive: allowDestructive,
		Only: onlyTools, Deny: denyTools, ToolArgs: overrides,
		AllowPlaintextAuth: allowPlaintextAuth, AllowPrivateHosts: allowPrivateHosts,
		AllowResourceMismatch: allowResourceMismatch, SkipEraCheck: skipEraCheck,
	}
}

// pacingSpec is the load the run may place on the server, from the flags.
//
// --concurrency 0 is documented as switching the burst off, but a zero in
// the spec means "unset" and takes the default of four workers, which is
// what a web client that sends a half-filled spec needs. So the flag's 0
// becomes the spec's explicit "no burst", a negative count.
func pacingSpec() engine.PacingSpec {
	workers := concurrency
	if workers == 0 {
		workers = engine.NoBurst
	}
	return engine.PacingSpec{
		Samples: samples, Concurrency: workers, RPS: rps,
		CallTimeout: callTimeout, Seed: seed, FillOptional: fillOpt,
		AllowLoad: allowLoad, MaxResources: maxRes, MaxPrompts: maxPrompts,
		Soak: soak,
	}
}

// outputSpec is what the run produces, from the flags.
func outputSpec(retainFor time.Duration) engine.OutputSpec {
	return engine.OutputSpec{
		Format: engine.Format(output), ReportDir: reportDir, Retain: retainFor,
		CaptureBodies: captureBodies, WithEvents: withEvents, WithGuidance: withGuidance,
		Verbose: verbose, NoColor: noColor, Interactive: interactive,
		OTLPEndpoint: otlpEndpoint, OTLPHeaders: otlpHeaders,
		OCSFEndpoint: ocsfEndpoint, OCSFHeaders: ocsfHeaders,
	}
}
