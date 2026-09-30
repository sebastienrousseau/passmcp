// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package diag carries passmcp's diagnostic output: what it is doing and why
// something was skipped, as distinct from the results it produces.
//
// Results go to stdout in the selected output format and must stay
// parseable; diagnostics therefore go to stderr, levelled, one line each,
// prefixed with the level so the stream stays greppable.
package diag

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"

	"satellion.com/passmcp/internal/termsafe"
)

// Level is the verbosity threshold.
type Level int

const (
	// LevelError reports only failures that stopped something from working.
	LevelError Level = iota
	// LevelWarn adds conditions passmcp worked around or declined to act on.
	LevelWarn
	// LevelInfo adds ordinary progress narration. This is the default.
	LevelInfo
	// LevelDebug adds detail only useful when diagnosing passmcp itself.
	LevelDebug
)

// EnvVar sets the level for a whole shell session.
const EnvVar = "PASSMCP_LOG_LEVEL"

// String returns the lowercase name accepted by ParseLevel.
func (l Level) String() string {
	switch l {
	case LevelError:
		return "error"
	case LevelWarn:
		return "warn"
	case LevelInfo:
		return "info"
	case LevelDebug:
		return "debug"
	}
	return fmt.Sprintf("Level(%d)", int(l))
}

// ParseLevel maps a name to a Level, case-insensitively.
func ParseLevel(name string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "error":
		return LevelError, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "info", "":
		return LevelInfo, nil
	case "debug":
		return LevelDebug, nil
	}
	return LevelInfo, fmt.Errorf("unknown log level %q (want error, warn, info or debug)", name)
}

// Format is how a diagnostic line is written.
type Format int

const (
	// FormatHuman is one prefixed line per message, the default. It is
	// meant to be read while the run is happening.
	FormatHuman Format = iota
	// FormatJSON is one JSON object per message, through log/slog. It is
	// meant to be shipped: a scheduled run's stderr is somebody's log
	// pipeline, and "WARN: something" is not a field anything can query.
	FormatJSON
)

// ParseFormat maps a flag value onto a Format.
func ParseFormat(name string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "human", "text":
		return FormatHuman, nil
	case "json":
		return FormatJSON, nil
	}
	return FormatHuman, fmt.Errorf("unknown log format %q (want human or json)", name)
}

var (
	mu     sync.RWMutex
	level            = LevelInfo
	output io.Writer = os.Stderr
	format           = FormatHuman
	logger *slog.Logger

	// run identifies the process-wide run in structured output, so lines
	// from a scheduled diagnostic can be joined to the report it produced.
	run string
)

// SetFormat selects how diagnostics are written.
func SetFormat(f Format) {
	mu.Lock()
	defer mu.Unlock()
	format = f
	logger = newLogger(output)
}

// SetRunID stamps every structured line with the run's trace id. It is
// deliberately not part of the human format: a person watching a single run
// does not need to be told which one it is on every line.
func SetRunID(id string) { mu.Lock(); run = id; mu.Unlock() }

// newLogger builds the slog handler. Caller holds mu.
//
// The handler does not filter. emit has already compared the message
// against passmcp's threshold by the time it gets here, and a handler with
// its own threshold would be a second source of truth that has to be kept
// in step with the first — which is a bug waiting for whichever order the
// caller happens to set them in.
func newLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// slogFor maps a passmcp level onto the slog level a record is written at.
func slogFor(l Level) slog.Level {
	switch l {
	case LevelError:
		return slog.LevelError
	case LevelWarn:
		return slog.LevelWarn
	case LevelDebug:
		return slog.LevelDebug
	default:
		return slog.LevelInfo
	}
}

// SetLevel sets the verbosity threshold.
func SetLevel(l Level) {
	mu.Lock()
	defer mu.Unlock()
	level = l
}

// CurrentLevel reports the threshold in force.
func CurrentLevel() Level { mu.RLock(); defer mu.RUnlock(); return level }

// SetOutput redirects diagnostics; nil restores stderr.
func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	if w == nil {
		w = os.Stderr
	}
	output = w
	if logger != nil {
		// Tests redirect output; a logger still holding the old writer would
		// send structured lines somewhere nobody is reading.
		logger = newLogger(output)
	}
}

// Enabled reports whether a message at l would be emitted.
func Enabled(l Level) bool { return l <= CurrentLevel() }

// emit writes one diagnostic. The parameter is named f rather than format
// because format is now package state.
func emit(l Level, f string, args ...any) {
	mu.RLock()
	threshold, w, fm, lg, runID := level, output, format, logger, run
	mu.RUnlock()
	if l > threshold {
		return
	}
	msg := strings.TrimRight(fmt.Sprintf(f, args...), "\n")
	if fm == FormatJSON {
		if lg == nil {
			mu.Lock()
			if logger == nil {
				logger = newLogger(w)
			}
			lg = logger
			mu.Unlock()
		}
		if runID != "" {
			lg.Log(context.Background(), slogFor(l), msg, slog.String("trace_id", runID))
			return
		}
		lg.Log(context.Background(), slogFor(l), msg)
		return
	}
	// The human format goes to a terminal, and a message often quotes
	// something a server chose. The JSON format above is left faithful:
	// its encoder escapes control characters, and a log pipeline is owed
	// what was actually said.
	_, _ = fmt.Fprintf(w, "%s: %s\n", strings.ToUpper(l.String()), termsafe.String(msg))
}

// Errorf reports a failure that stopped something from working.
func Errorf(format string, args ...any) { emit(LevelError, format, args...) }

// Warnf reports a condition passmcp worked around or declined to act on.
func Warnf(format string, args ...any) { emit(LevelWarn, format, args...) }

// Infof reports ordinary progress.
func Infof(format string, args ...any) { emit(LevelInfo, format, args...) }

// Debugf reports detail useful only when diagnosing passmcp itself.
func Debugf(format string, args ...any) { emit(LevelDebug, format, args...) }
