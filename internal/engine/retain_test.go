// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp/internal/diag"
)

func TestParseRetention(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"":      0,
		"  ":    0,
		"30d":   30 * 24 * time.Hour,
		"720h":  720 * time.Hour,
		" 90m ": 90 * time.Minute,
	} {
		got, err := ParseRetention(in)
		if err != nil || got != want {
			t.Errorf("ParseRetention(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"0d", "-3d", "xd", "soon", "-1h", "0s"} {
		if _, err := ParseRetention(bad); err == nil {
			t.Errorf("ParseRetention(%q) accepted", bad)
		}
	}
}

// AC: GDPR-05
func TestSweepDeletesOnlyPassmcpsOldFilesAndLogsEach(t *testing.T) {
	var logs bytes.Buffer
	diag.SetOutput(&logs)
	defer diag.SetOutput(nil)

	dir := t.TempDir()
	now := time.Now()
	old := now.Add(-40 * 24 * time.Hour)
	files := map[string]time.Time{
		"policy.json":     old, // passmcp's, old: deleted
		"report.json":     now, // passmcp's, recent: kept
		"telemetry.har":   old, // passmcp's, old: deleted
		"customer.csv":    old, // not passmcp's: never touched
		"report.json.bak": old, // not passmcp's name: never touched
	}
	for name, at := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "report.md"), 0o750); err != nil {
		t.Fatal(err)
	}

	if err := sweepReportDir(dir, 30*24*time.Hour, now); err != nil {
		t.Fatal(err)
	}
	for name, gone := range map[string]bool{"policy.json": true, "telemetry.har": true, "report.json": false, "customer.csv": false, "report.json.bak": false, "report.md": false} {
		_, err := os.Stat(filepath.Join(dir, name))
		if gone != os.IsNotExist(err) {
			t.Errorf("%s: gone=%v, want %v", name, os.IsNotExist(err), gone)
		}
	}
	for _, name := range []string{"policy.json", "telemetry.har"} {
		if !strings.Contains(logs.String(), "retention: deleted "+filepath.Join(dir, name)) {
			t.Errorf("deleting %s was not logged:\n%s", name, logs.String())
		}
	}
	if strings.Contains(logs.String(), "customer.csv") {
		t.Errorf("a foreign file was mentioned:\n%s", logs.String())
	}

	if err := sweepReportDir(filepath.Join(dir, "absent"), time.Hour, now); err == nil {
		t.Error("an unreadable directory was not an error")
	}
}
