// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package fleet

import "satellion.com/passmcp/internal/ocsf"

// Drift is every change in the summary in the shape the OCSF export takes,
// each carrying the attestation digests of both runs it was found between.
func (s *Summary) Drift() []ocsf.Drift {
	var out []ocsf.Drift
	for _, srv := range s.Servers {
		for _, c := range srv.Changes {
			subject := c.Tool
			if subject == "" {
				subject = c.Check
			}
			out = append(out, ocsf.Drift{
				Server:            srv.Name,
				Endpoint:          srv.Endpoint,
				Kind:              c.Kind,
				Tool:              subject,
				Severity:          c.Severity,
				Detail:            c.Detail,
				Before:            c.Before,
				After:             c.After,
				BeforeAttestation: srv.Previous,
				AfterAttestation:  srv.Attestation,
				At:                s.Started,
			})
		}
	}
	return out
}
