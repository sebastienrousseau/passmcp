// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build linux

package witness

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

const helperEnv = "PASSMCP_WITNESS_HELPER"

// TestMain lets the test binary run as the observed process: it connects a
// UDP socket to a documentation-only address (no packet needs to go
// anywhere for a UDP connect), listens on every interface, opens a file for
// writing, and waits.
func TestMain(m *testing.M) {
	if path := os.Getenv(helperEnv); path != "" {
		c, err := net.Dial("udp", "192.0.2.1:9")
		if err != nil {
			os.Exit(3)
		}
		ln, err := net.Listen("tcp4", "0.0.0.0:0")
		if err != nil {
			os.Exit(5)
		}
		defer func() { _ = ln.Close() }()
		f, err := os.Create(path)
		if err != nil {
			os.Exit(4)
		}
		_, _ = os.Stdout.WriteString("ready\n")
		time.Sleep(20 * time.Second)
		_ = c.Close()
		_ = f.Close()
		return
	}
	os.Exit(m.Run())
}

func TestTakeSeesAProcessGroupsSocketsAndWrites(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "written")
	cmd := exec.Command(self) //nolint:gosec // this test binary, re-executed
	cmd.Env = append(os.Environ(), helperEnv+"="+path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	buf := make([]byte, 6)
	if _, err := out.Read(buf); err != nil {
		t.Fatalf("the helper never got ready: %v", err)
	}

	s, err := Take(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Processes[cmd.Process.Pid]; !ok {
		t.Errorf("the process is not in its own group: %v", s.Processes)
	}
	var sawUDP bool
	for _, c := range s.Conns {
		if c.Proto == "udp" && c.Remote == "192.0.2.1:9" {
			sawUDP = true
		}
	}
	if !sawUDP {
		t.Errorf("the connected UDP socket was not seen: %+v", s.Conns)
	}
	if !s.Writes[path] {
		t.Errorf("the file open for writing was not seen: %v", s.Writes)
	}
	var sawListen bool
	for _, l := range s.Listens {
		sawListen = sawListen || (l.Proto == "tcp" && l.AllInterfaces())
	}
	if !sawListen {
		t.Errorf("the socket listening on every interface was not seen: %+v", s.Listens)
	}

	// Through the watcher: all of it was open at the baseline, so nothing
	// is reported.
	w, err := Start(cmd.Process.Pid, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	o := w.Stop()
	if len(o.Conns)+len(o.Writes)+len(o.Processes) != 0 || o.Samples == 0 {
		t.Errorf("bootstrap was reported as behaviour: %+v", o)
	}
	// A listener is the exception: bound at start, it is still exposure.
	if len(o.Listening) == 0 {
		t.Errorf("the bootstrap listener was dropped: %+v", o)
	}
}

func TestTakeOnAGroupThatDoesNotExist(t *testing.T) {
	s, err := Take(1 << 30)
	if err != nil || len(s.Processes) != 0 {
		t.Errorf("Take = %+v, %v", s, err)
	}
	old := procRoot
	procRoot = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { procRoot = old })
	if _, err := Take(1); err == nil {
		t.Error("an unreadable /proc was not an error")
	}
}

func TestRSSSumsTheGroupAndSaysWhenItIsGone(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self) //nolint:gosec // this test binary, re-executed
	cmd.Env = append(os.Environ(), helperEnv+"="+filepath.Join(t.TempDir(), "written"))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	buf := make([]byte, 6)
	if _, err := out.Read(buf); err != nil {
		t.Fatalf("the helper never got ready: %v", err)
	}
	n, err := RSS(cmd.Process.Pid)
	if err != nil || n <= 0 {
		t.Errorf("RSS = %d, %v", n, err)
	}
	if _, err := RSS(1 << 30); !errors.Is(err, ErrGone) {
		t.Errorf("a group that does not exist: %v", err)
	}
	old := procRoot
	procRoot = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { procRoot = old })
	if _, err := RSS(1); err == nil || errors.Is(err, ErrGone) {
		t.Errorf("an unreadable /proc: %v", err)
	}
}
