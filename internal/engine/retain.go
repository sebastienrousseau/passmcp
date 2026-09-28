// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"satellion.com/passmcp/internal/diag"
)

// ParseRetention reads --retain: a Go duration ("720h"), or a whole number
// of days ("30d"), which is how retention periods are written everywhere
// outside Go. Empty means no retention: nothing is deleted.
func ParseRetention(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("--retain %q: a number of days must be a positive whole number", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("--retain %q: want a positive duration such as 720h or 30d", s)
	}
	return d, nil
}

// reportFiles are the names passmcp writes into a report directory. Only
// these are ever deleted: a report directory is often a directory the
// operator also uses for other things, and retention must not reach them.
var reportFiles = map[string]bool{
	"report.json": true, "report.md": true, "report.html": true, "report.txt": true,
	"report.sarif": true, "report.junit.xml": true, "attestation.json": true,
	"telemetry.ndjson": true, "telemetry.har": true, "policy.json": true,
}

// sweepReportDir deletes passmcp's own files in dir that are older than
// retain, logging each by name on stderr.
//
// The files a run writes replace themselves, so this matters most for the
// ones a run writes only sometimes — policy.json, from a run that applied a
// policy — which would otherwise outlive the decision they record. Only
// regular files directly in dir with one of passmcp's names are considered.
func sweepReportDir(dir string, retain time.Duration, now time.Time) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	cutoff := now.Add(-retain)
	for _, e := range entries {
		if !e.Type().IsRegular() || !reportFiles[e.Name()] {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.ModTime().Before(cutoff) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("retention: %w", err)
		}
		diag.Infof("retention: deleted %s, last written %s, older than %s", path, info.ModTime().UTC().Format(time.RFC3339), retain)
	}
	return nil
}
