// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"context"

	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/ocsf"
)

// ExportOCSF posts the run's OCSF events to the endpoint the operator named
// with --ocsf-endpoint, and does nothing when none was named.
//
// It is the OCSF twin of ExportTraces: an exporter the operator points at
// their own SIEM, never on by default, which is what keeps it inside ADR 0006.
// Announcing the destination before anything leaves is the surface's job,
// because only the surface knows where its operator is reading.
func (r *Result) ExportOCSF(ctx context.Context, spec RunSpec) error {
	if spec.Output.OCSFEndpoint == "" || r.Report == nil {
		return nil
	}
	headers, err := parseHeaders(spec.Output.OCSFHeaders)
	if err != nil {
		return err
	}
	return ocsf.Sender{Endpoint: spec.Output.OCSFEndpoint, Headers: headers}.Send(ctx, r.OCSFEvents())
}

// parseHeaders reads "Name: value" pairs, as --otlp-header does.
func parseHeaders(raw []string) (map[string]string, error) {
	headers := map[string]string{}
	for _, h := range raw {
		k, v, err := creds.ParseHeader(h)
		if err != nil {
			return nil, err
		}
		headers[k] = v
	}
	return headers, nil
}
