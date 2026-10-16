// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build windows

package transport_test

import (
	"os"
	"testing"
	"time"

	"satellion.com/passmcp/transport"
)

// helperEnv selects what the re-executed test binary does instead of
// running the tests. The shell-script fixtures the other stdio tests use do
// not exist on Windows, so the fixture here is this binary itself.
const helperEnv = "PASSMCP_TRANSPORT_HELPER"

func TestMain(m *testing.M) {
	if mode := os.Getenv(helperEnv); mode != "" {
		runHelper(mode)
		return
	}
	os.Exit(m.Run())
}

// runHelper is the fixture server. "ignore-eof" ignores its stdin and
// stays up, the misbehaviour Close has to force.
func runHelper(mode string) {
	switch mode {
	case "ignore-eof":
		time.Sleep(time.Minute)
		os.Exit(0)
	default:
		os.Exit(2)
	}
}

// startHelper runs this test binary as a stdio server in the given mode.
func startHelper(t *testing.T, mode string, grace time.Duration) *transport.Stdio {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return start(t, transport.StdioConfig{
		Command:       exe,
		Args:          []string{"-test.run=^$"},
		Inject:        []string{helperEnv + "=" + mode},
		ShutdownGrace: grace,
	})
}

// Windows has no SIGTERM. os.Process.Signal returns an error for it, so a
// Close that sent one anyway recorded a signal that never left passmcp,
// then waited the whole SIGTERM grace for nothing before killing. A forced
// Close goes straight to the kill and says so.
func TestStdioForcedCloseOnWindowsKillsWithoutSIGTERM(t *testing.T) {
	const grace = 300 * time.Millisecond
	s := startHelper(t, "ignore-eof", grace)

	began := time.Now()
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	took := time.Since(began)

	c := s.Custody()
	if !c.Forced {
		t.Fatal("a server that ignores EOF was not recorded as forced")
	}
	if c.Signalled != "TerminateProcess" {
		t.Errorf("Signalled = %q, want TerminateProcess; Windows sends no SIGTERM", c.Signalled)
	}
	if c.Err != nil {
		t.Errorf("Custody.Err = %v; nothing unsupported should have been attempted", c.Err)
	}
	// The SIGTERM grace is two seconds. Waiting it out would put Close
	// well past this bound.
	if limit := grace + time.Second; took > limit {
		t.Errorf("Close took %s, want under %s: it waited for a signal Windows cannot send", took, limit)
	}
	if exited, _ := s.Exited(); !exited {
		t.Error("Close returned while the process was still running")
	}
}
