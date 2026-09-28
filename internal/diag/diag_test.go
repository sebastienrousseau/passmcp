// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package diag

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestParseLevelAndString(t *testing.T) {
	cases := map[string]Level{"error": LevelError, "WARN": LevelWarn, "warning": LevelWarn, "info": LevelInfo, "": LevelInfo, " Debug ": LevelDebug}
	for in, want := range cases {
		got, err := ParseLevel(in)
		if err != nil || got != want {
			t.Errorf("ParseLevel(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseLevel("loud"); err == nil || !strings.Contains(err.Error(), "unknown log level") {
		t.Errorf("bad level: %v", err)
	}
	for l, s := range map[Level]string{LevelError: "error", LevelWarn: "warn", LevelInfo: "info", LevelDebug: "debug", Level(9): "Level(9)"} {
		if l.String() != s {
			t.Errorf("%d.String() = %q, want %q", int(l), l.String(), s)
		}
	}
}

func TestEmitRespectsLevelAndOutput(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	defer SetOutput(nil)
	defer SetLevel(LevelInfo)

	SetLevel(LevelWarn)
	if CurrentLevel() != LevelWarn || !Enabled(LevelError) || !Enabled(LevelWarn) || Enabled(LevelInfo) || Enabled(LevelDebug) {
		t.Error("Enabled thresholds")
	}
	Errorf("boom %d", 1)
	Warnf("careful\n")
	Infof("hidden")
	Debugf("hidden too")
	got := buf.String()
	if got != "ERROR: boom 1\nWARN: careful\n" {
		t.Errorf("output = %q", got)
	}
	buf.Reset()
	SetLevel(LevelDebug)
	Infof("i")
	Debugf("d")
	if buf.String() != "INFO: i\nDEBUG: d\n" {
		t.Errorf("debug output = %q", buf.String())
	}
	SetOutput(nil)
	// nil restores stderr: emitting must not write to buf any more.
	buf.Reset()
	SetLevel(LevelError)
	Errorf("to stderr")
	if buf.Len() != 0 {
		t.Error("SetOutput(nil) did not restore stderr")
	}
	_ = os.Stderr
}

// --- structured output ----------------------------------------------------

func TestJSONFormatEmitsOneObjectPerLine(t *testing.T) {
	var buf bytes.Buffer
	t.Cleanup(func() { SetOutput(nil); SetFormat(FormatHuman); SetRunID(""); SetLevel(LevelInfo) })

	SetOutput(&buf)
	SetFormat(FormatJSON)
	SetRunID("0123456789abcdef0123456789abcdef")
	SetLevel(LevelDebug)

	Errorf("boom %d", 1)
	Warnf("careful")
	Infof("progress")
	Debugf("detail")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("got %d lines, want 4:\n%s", len(lines), buf.String())
	}
	wantLevels := []string{"ERROR", "WARN", "INFO", "DEBUG"}
	wantMsgs := []string{"boom 1", "careful", "progress", "detail"}
	for i, line := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d is not JSON: %v\n%s", i, err, line)
		}
		if rec["level"] != wantLevels[i] {
			t.Errorf("line %d level = %v, want %s", i, rec["level"], wantLevels[i])
		}
		if rec["msg"] != wantMsgs[i] {
			t.Errorf("line %d msg = %v, want %q", i, rec["msg"], wantMsgs[i])
		}
		if rec["trace_id"] != "0123456789abcdef0123456789abcdef" {
			t.Errorf("line %d has no trace id: %v", i, rec["trace_id"])
		}
		if rec["time"] == nil {
			t.Errorf("line %d has no timestamp", i)
		}
	}
}

// TestJSONFormatHonoursLevel is the property a log pipeline depends on: the
// handler's own threshold and passmcp's must agree, whichever is set first.
func TestJSONFormatHonoursLevel(t *testing.T) {
	for _, order := range []string{"level-then-format", "format-then-level"} {
		t.Run(order, func(t *testing.T) {
			var buf bytes.Buffer
			t.Cleanup(func() { SetOutput(nil); SetFormat(FormatHuman); SetLevel(LevelInfo) })
			SetOutput(&buf)
			if order == "level-then-format" {
				SetLevel(LevelError)
				SetFormat(FormatJSON)
			} else {
				SetFormat(FormatJSON)
				SetLevel(LevelError)
			}
			Infof("should not appear")
			Errorf("should appear")
			if strings.Contains(buf.String(), "should not appear") {
				t.Errorf("info survived an error threshold:\n%s", buf.String())
			}
			if !strings.Contains(buf.String(), "should appear") {
				t.Errorf("error was dropped:\n%s", buf.String())
			}
		})
	}
}

// TestJSONFormatFollowsOutputChanges covers the order a real caller uses:
// the format is chosen once at startup, and the writer changes afterwards.
// Without rebuilding the handler, every structured line would keep going to
// the writer that was current when the format was set.
func TestJSONFormatFollowsOutputChanges(t *testing.T) {
	var first, second bytes.Buffer
	t.Cleanup(func() { SetOutput(nil); SetFormat(FormatHuman); SetLevel(LevelInfo) })

	SetOutput(&first)
	SetFormat(FormatJSON)
	Infof("to the first")

	SetOutput(&second)
	Infof("to the second")

	if !strings.Contains(first.String(), "to the first") {
		t.Errorf("first writer missed its line:\n%s", first.String())
	}
	if strings.Contains(first.String(), "to the second") {
		t.Errorf("the first writer kept receiving after SetOutput:\n%s", first.String())
	}
	if !strings.Contains(second.String(), "to the second") {
		t.Errorf("second writer received nothing:\n%s", second.String())
	}
}

func TestParseFormat(t *testing.T) {
	for in, want := range map[string]Format{"": FormatHuman, "human": FormatHuman, "text": FormatHuman, "JSON": FormatJSON, " json ": FormatJSON} {
		got, err := ParseFormat(in)
		if err != nil || got != want {
			t.Errorf("ParseFormat(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseFormat("logfmt"); err == nil {
		t.Error("ParseFormat accepted an unsupported format")
	}
}

// TestHumanFormatUnchanged pins the default. Somebody reads this stream
// while the run is happening, and a prefixed line is what they grep.
func TestHumanFormatUnchanged(t *testing.T) {
	var buf bytes.Buffer
	t.Cleanup(func() { SetOutput(nil); SetLevel(LevelInfo) })
	SetOutput(&buf)
	SetFormat(FormatHuman)
	Warnf("plain %s", "line")
	if got := buf.String(); got != "WARN: plain line\n" {
		t.Errorf("human output = %q", got)
	}
}
