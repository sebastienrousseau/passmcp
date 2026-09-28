// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"satellion.com/passmcp/internal/witness"
)

// What the server did after its handshake, read from outside. The witness
// package says how and where it cannot see; these findings turn what it
// saw into the three questions the roadmap asked: did the server open a
// connection nobody asked for, write somewhere it should not, or start a
// process.

// witnessInterval is how often the process group is sampled. Anything
// opened and closed between two samples is not seen, and every finding
// says so.
const witnessInterval = 100 * time.Millisecond

func (s *Session) startWitness() {
	if s.Pipe == nil || s.witness != nil || s.witnessed != nil {
		return
	}
	w, err := witness.Start(s.Pipe.PID(), witnessInterval)
	if err != nil {
		s.witnessErr = err
		return
	}
	s.witness = w
}

// stopWitness ends sampling, once.
func (s *Session) stopWitness() {
	if s.witness == nil {
		return
	}
	o := s.witness.Stop()
	s.witnessed = &o
	s.witness = nil
}

// checkWitness reports the three post-handshake observations.
func checkWitness(s *Session) []Finding {
	s.stopWitness()
	conns := s.check("stdio.post_init_connections", "No connection nobody asked for, after the handshake")
	writes := s.check("stdio.post_init_writes", "No writes outside the working directory, after the handshake")
	procs := s.check("stdio.post_init_processes", "Processes started after the handshake")

	if s.witnessed == nil {
		reason := "the handshake did not complete, so there is no after to watch"
		switch {
		case errors.Is(s.witnessErr, witness.ErrUnsupported):
			reason = s.witnessErr.Error()
		case s.witnessErr != nil:
			reason = "the witness could not start: " + s.witnessErr.Error()
		}
		return []Finding{conns.skip(reason), writes.skip(reason), procs.skip(reason), checkBindAll(s, reason)}
	}
	o := *s.witnessed
	limit := fmt.Sprintf("sampled every %s, %d time(s); anything opened and closed between two samples is not seen", o.Interval, o.Samples)

	var out []Finding
	var direct []string
	loopback := 0
	for _, c := range o.Conns {
		host, _, _ := net.SplitHostPort(c.Remote)
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			loopback++ // passmcp's own proxy, or a local service
			continue
		}
		direct = append(direct, c.Proto+" "+c.Remote)
	}
	if len(direct) > 0 {
		out = append(out, conns.ev(direct...).warn(
			fmt.Sprintf("opened %s to a non-loopback address after the handshake, not through passmcp's proxy: %s (%s)",
				plural(len(direct), "connection"), list(direct), limit),
			"a server that answers tool calls should reach only what those calls need, through the proxy its environment names. A socket opened around HTTP_PROXY is invisible to egress.hosts, and after the handshake every action is one a request caused"))
	} else {
		detail := "no connection to a non-loopback address appeared after the handshake (" + limit + ")"
		if loopback > 0 {
			detail = fmt.Sprintf("%s; %s to loopback, which includes passmcp's own proxy", detail, plural(loopback, "connection"))
		}
		out = append(out, conns.info(detail))
	}

	var outside []string
	allowed := writeRoots(s)
	for _, p := range o.Writes {
		if !under(p, allowed) {
			outside = append(outside, p)
		}
	}
	if len(outside) > 0 {
		out = append(out, writes.ev(outside...).warn(
			fmt.Sprintf("opened %s for writing outside its working directory after the handshake: %s (%s)",
				plural(len(outside), "file"), list(outside), limit),
			"write only under the working directory the host gave the server, or a path the operator configured. A read-only tool call that leaves a file open for writing elsewhere is doing something the caller did not ask for"))
	} else {
		out = append(out, writes.info("nothing was opened for writing outside the working directory after the handshake ("+limit+")"))
	}

	out = append(out, checkBindAll(s, ""))

	if len(o.Processes) > 0 {
		out = append(out, procs.ev(o.Processes...).info(
			fmt.Sprintf("started %s after the handshake: %s (%s)", plural(len(o.Processes), "process"), list(o.Processes), limit)))
	} else {
		out = append(out, procs.info("no new process appeared in the server's process group after the handshake ("+limit+")"))
	}
	return out
}

// writeRoots are where a server may write without comment: its working
// directory, passmcp's scratch home when one was planted, and the kernel's
// pseudo-filesystems.
func writeRoots(s *Session) []string {
	roots := []string{"/dev/", "/proc/", "/sys/"}
	dir := ""
	if s.Opts.Stdio != nil {
		dir = s.Opts.Stdio.Dir
	}
	if dir == "" {
		dir, _ = os.Getwd() // the child inherits passmcp's
	}
	if dir != "" {
		roots = append(roots, dir)
	}
	if s.Canary != nil {
		roots = append(roots, s.Canary.Dir())
	}
	return roots
}

// under reports whether p is one of roots or inside one. The paths are
// /proc's, which are POSIX whatever platform passmcp was built for, so they
// are cleaned as slash paths rather than with filepath.
func under(p string, roots []string) bool {
	for _, r := range roots {
		r = path.Clean(r)
		if p == r || strings.HasPrefix(p, strings.TrimSuffix(r, "/")+"/") {
			return true
		}
	}
	return false
}
