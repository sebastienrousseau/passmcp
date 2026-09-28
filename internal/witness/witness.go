// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package witness records what a stdio server does after its handshake:
// the connections it opens, the files it opens for writing, and the
// processes it starts.
//
// The roadmap asked for a sandbox that snaps shut when the handshake
// completes. That cannot be built from outside: Landlock and seccomp are
// restrictions a process applies to itself, and passmcp does not control the
// server's code. What can be done from outside, without root and without a
// syscall tracer, is to look. On Linux every process publishes its open
// file descriptors and its network sockets under /proc, so sampling the
// server's process group shows what it has open at each moment.
//
// Two phases, on a protocol event rather than a timer: whatever is open when
// the handshake completes is bootstrap — an interpreter loading, packages
// resolving — and is the baseline. Only what appears after it is reported,
// because after the handshake the only reason to act is a request passmcp
// sent. The limit is stated rather than hidden: a connection opened and
// closed between two samples is not seen, so the absence of a finding is
// not a proof.
package witness

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrUnsupported means this platform does not publish what the witness
// reads. It is a reason to skip, never a clean result.
var ErrUnsupported = errors.New("witness: only Linux publishes a process's sockets and open files under /proc")

// ErrGone means no process in the group was there to read: the server has
// exited, or was never in the group passmcp was told to watch.
var ErrGone = errors.New("witness: no process in the group")

// parseStatmResident reads the resident-set size, in pages, from one
// process's /proc/<pid>/statm. The file is seven integers on one line and
// the second is the resident count; anything else is not a statm line.
func parseStatmResident(line string) (int64, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0, false
	}
	n, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// Conn is one socket with a remote end.
type Conn struct {
	Proto  string `json:"proto"`
	Remote string `json:"remote"`
}

// Listen is one TCP socket accepting connections, and the local address it
// is bound to.
type Listen struct {
	Proto string `json:"proto"`
	Local string `json:"local"`
}

// AllInterfaces reports whether the socket is bound to every interface
// (0.0.0.0 or ::) rather than to one address, which is what makes a local
// server reachable from the rest of the network.
func (l Listen) AllInterfaces() bool {
	host, _, err := net.SplitHostPort(l.Local)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}

// Port is the port the socket listens on.
func (l Listen) Port() string {
	_, port, _ := net.SplitHostPort(l.Local)
	return port
}

// Snapshot is what a process group had open at one moment.
type Snapshot struct {
	// Processes maps a pid to its command line.
	Processes map[int]string
	// Conns maps a socket inode to its connection.
	Conns map[string]Conn
	// Listens maps a socket inode to a listening TCP socket.
	Listens map[string]Listen
	// Writes are paths open for writing.
	Writes map[string]bool
}

// Observed is everything that appeared after the baseline.
type Observed struct {
	Processes []string `json:"processes,omitempty"`
	Conns     []Conn   `json:"connections,omitempty"`
	Writes    []string `json:"writes,omitempty"`
	// Listening is every listening socket the group held, from the baseline
	// on. Unlike the others it includes the bootstrap: a server binds its
	// port while it starts, and that is exactly the exposure worth seeing.
	Listening []Listen `json:"listening,omitempty"`
	// Samples is how many snapshots were taken after the baseline.
	Samples  int           `json:"samples"`
	Interval time.Duration `json:"interval_ns"`
}

// Watcher samples a process group until stopped.
type Watcher struct {
	pgid     int
	interval time.Duration
	take     func(int) (Snapshot, error)

	mu       sync.Mutex
	base     Snapshot
	observed Observed
	seenProc map[int]bool
	seenConn map[string]bool
	seenW    map[string]bool
	seenL    map[string]bool

	stop chan struct{}
	done chan struct{}
}

// Start takes the baseline now and samples every interval until Stop.
func Start(pgid int, interval time.Duration) (*Watcher, error) {
	return start(pgid, interval, Take)
}

func start(pgid int, interval time.Duration, take func(int) (Snapshot, error)) (*Watcher, error) {
	base, err := take(pgid)
	if err != nil {
		return nil, err
	}
	w := &Watcher{
		pgid: pgid, interval: interval, take: take, base: base,
		observed: Observed{Interval: interval},
		seenProc: map[int]bool{}, seenConn: map[string]bool{}, seenW: map[string]bool{},
		seenL: map[string]bool{},
		stop:  make(chan struct{}), done: make(chan struct{}),
	}
	w.noteListens(base)
	go w.loop()
	return w, nil
}

func (w *Watcher) loop() {
	defer close(w.done)
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-w.stop:
			w.sample() // one last look, so a short run still gets a sample
			return
		case <-t.C:
			w.sample()
		}
	}
}

func (w *Watcher) sample() {
	s, err := w.take(w.pgid)
	if err != nil {
		// The group may have exited; what was seen so far stands.
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.observed.Samples++
	for pid, cmd := range s.Processes {
		if _, bootstrap := w.base.Processes[pid]; bootstrap || w.seenProc[pid] {
			continue
		}
		w.seenProc[pid] = true
		w.observed.Processes = append(w.observed.Processes, cmd)
	}
	for inode, c := range s.Conns {
		if _, bootstrap := w.base.Conns[inode]; bootstrap {
			continue
		}
		key := c.Proto + " " + c.Remote
		if w.seenConn[key] {
			continue
		}
		w.seenConn[key] = true
		w.observed.Conns = append(w.observed.Conns, c)
	}
	for p := range s.Writes {
		if w.base.Writes[p] || w.seenW[p] {
			continue
		}
		w.seenW[p] = true
		w.observed.Writes = append(w.observed.Writes, p)
	}
	w.noteListens(s)
}

// noteListens records every listening socket in a snapshot once, baseline
// included. The caller holds the lock, or has not started the loop yet.
func (w *Watcher) noteListens(s Snapshot) {
	for _, l := range s.Listens {
		key := l.Proto + " " + l.Local
		if w.seenL[key] {
			continue
		}
		w.seenL[key] = true
		w.observed.Listening = append(w.observed.Listening, l)
	}
}

// Stop ends sampling and returns what appeared after the baseline, sorted.
func (w *Watcher) Stop() Observed {
	select {
	case <-w.stop:
	default:
		close(w.stop)
	}
	<-w.done
	w.mu.Lock()
	defer w.mu.Unlock()
	o := w.observed
	sort.Strings(o.Processes)
	sort.Strings(o.Writes)
	sort.Slice(o.Listening, func(i, j int) bool {
		if o.Listening[i].Local != o.Listening[j].Local {
			return o.Listening[i].Local < o.Listening[j].Local
		}
		return o.Listening[i].Proto < o.Listening[j].Proto
	})
	sort.Slice(o.Conns, func(i, j int) bool {
		if o.Conns[i].Remote != o.Conns[j].Remote {
			return o.Conns[i].Remote < o.Conns[j].Remote
		}
		return o.Conns[i].Proto < o.Conns[j].Proto
	})
	return o
}

// --- parsing, platform-neutral so it is tested everywhere --------------------

// parseStatPgrp returns the process group from a /proc/<pid>/stat line.
// The command name is in parentheses and may itself contain spaces and
// parentheses, so the fields are read after the last ')'.
func parseStatPgrp(line string) (int, error) {
	i := strings.LastIndexByte(line, ')')
	if i < 0 {
		return 0, fmt.Errorf("witness: malformed stat line")
	}
	f := strings.Fields(line[i+1:])
	if len(f) < 3 {
		return 0, fmt.Errorf("witness: short stat line")
	}
	return strconv.Atoi(f[2]) // state, ppid, pgrp
}

// openForWrite reads the flags line of /proc/<pid>/fdinfo/<fd>, which is
// octal, and reports whether the descriptor can write.
func openForWrite(fdinfo string) bool {
	for _, l := range strings.Split(fdinfo, "\n") {
		if v, ok := strings.CutPrefix(l, "flags:"); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 8, 64)
			return err == nil && n&3 != 0 // O_WRONLY or O_RDWR
		}
	}
	return false
}

// decodeAddr reads a /proc/net address, "0100007F:1F90": the IP as hex in
// host (little-endian) order, word by word for IPv6, and the port as hex.
func decodeAddr(s string) (string, bool) {
	ipHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return "", false
	}
	raw, err := hex.DecodeString(ipHex)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", false
	}
	ip := make(net.IP, len(raw))
	for w := 0; w < len(raw); w += 4 {
		ip[w], ip[w+1], ip[w+2], ip[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return "", false
	}
	return net.JoinHostPort(ip.String(), strconv.FormatUint(port, 10)), true
}

// parseNetTable maps socket inodes to connections from one /proc/net/*
// table. Sockets with no remote end — listeners, unconnected datagram
// sockets — are left out: they have not reached anything.
func parseNetTable(proto, table string) map[string]Conn {
	out := map[string]Conn{}
	lines := strings.Split(table, "\n")
	for _, l := range lines[min(1, len(lines)):] { // the first line is a header
		f := strings.Fields(l)
		if len(f) < 10 {
			continue
		}
		remote, ok := decodeAddr(f[2])
		if !ok {
			continue
		}
		host, port, _ := net.SplitHostPort(remote)
		if port == "0" || net.ParseIP(host).IsUnspecified() {
			continue
		}
		out[f[9]] = Conn{Proto: proto, Remote: remote}
	}
	return out
}

// tcpListen is the state /proc/net/tcp gives a listening socket.
const tcpListen = "0A"

// parseListenTable maps socket inodes to listening sockets from one
// /proc/net/tcp or tcp6 table.
func parseListenTable(proto, table string) map[string]Listen {
	out := map[string]Listen{}
	lines := strings.Split(table, "\n")
	for _, l := range lines[min(1, len(lines)):] { // the first line is a header
		f := strings.Fields(l)
		if len(f) < 10 || f[3] != tcpListen {
			continue
		}
		local, ok := decodeAddr(f[1])
		if !ok {
			continue
		}
		out[f[9]] = Listen{Proto: proto, Local: local}
	}
	return out
}
