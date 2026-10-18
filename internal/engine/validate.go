// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"errors"
	"fmt"
	"strings"

	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/probe"
)

// validateOutputAndPhases checks the format, the gate policy and the
// phase names.
func (s RunSpec) validateOutputAndPhases() error {
	if !s.Output.Format.Valid() {
		return fmt.Errorf("output format %q is not one of %v", s.Output.Format, Formats)
	}
	if s.Output.HTMLAssets && strings.TrimSpace(s.Output.ReportDir) == "" {
		// The stylesheet has to land somewhere the page can reach it, and
		// stdout carries one document. Asked for and silently not done
		// would leave a page linking a file that does not exist.
		return errors.New("--html-assets writes report.css into the report directory, so it needs --report-dir")
	}
	if s.Gate != nil {
		if err := s.Gate.Validate(); err != nil {
			return err
		}
	}
	for _, name := range append(append([]string{}, s.Phases.Only...), s.Phases.Skip...) {
		if !knownPhase(name) {
			return fmt.Errorf("unknown phase %q; known phases are %s", name, strings.Join(probe.PhaseNames(), ", "))
		}
	}
	return nil
}

// validateCredentials resolves the credentials and refuses any over stdio.
func (s RunSpec) validateCredentials() error {
	c, err := s.Credentials()
	if err != nil {
		return err
	}
	if s.Target.Stdio() && c.Effective() != creds.ModeNone {
		return fmt.Errorf("credentials have no meaning over stdio: a child process has no origin to authorize against, "+
			"and %s would be sent nowhere. Pass what the server needs in its arguments, or forward a variable with --stdio-env", c.Effective())
	}
	return nil
}
