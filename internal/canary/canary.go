// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package canary finds out whether a server goes looking for credentials
// it was never given.
//
// The egress witness says where a server went. It cannot say what it took
// with it, and the thing worth taking is sitting in the same place on
// almost every developer machine: ~/.ssh/id_rsa, ~/.aws/credentials, a
// .env beside the project. A server that reads those has done something no
// catalogue declares and no protocol check can see.
//
// Once passmcp starts the process it decides where HOME points. Pointing it
// at a scratch directory seeded with decoys turns "did it go looking" into
// something with an answer, and costs the server nothing if it did not: a
// well-behaved server never opens a file it was not asked about.
//
// Each decoy carries a marker found nowhere else on the machine, so the
// same run answers a second question. A marker that leaves — in a request
// body, or handed back to passmcp in a tool result — is not a suspicion. It
// is the file, in transit, with a label on it.
//
// # The instrument checks itself
//
// The obvious witness for "was this read" is the access time moving, and
// it is unreliable in a way that matters. macOS on APFS does not update it
// on an ordinary read at all; Linux mounted `relatime` updates it only
// sometimes, and `noatime` never. A check resting on that would report a
// clean result on a machine where it was incapable of reporting anything
// else, which is the worst outcome available to a security check.
//
// So Seed measures it. It writes a probe file, backdates it, reads it
// back, and looks. What the caller gets is not just the readings but
// whether the instrument works here at all — and the check built on this
// says "cannot tell" rather than "nothing found" when it does not.
package canary

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// backdate is how far into the past a seeded file's timestamps are set.
//
// Comfortably past the one-day threshold Linux's `relatime` uses to decide
// whether a read is worth recording, so a filesystem that tracks access
// times at all will record this one.
const backdate = 72 * time.Hour

// Decoy is one planted credential.
type Decoy struct {
	// Name is where it sits relative to the scratch home, using forward
	// slashes, because that is how a report should read on any platform.
	Name string `json:"name"`
	// Path is the real location.
	Path string `json:"-"`
	// Marker is the unique string inside it.
	Marker string `json:"-"`
	// Read is whether the access time moved. Meaningless unless the
	// canary reports that access times work here.
	Read bool `json:"read"`

	seeded time.Time
}

// Canary is a scratch home full of things worth stealing.
type Canary struct {
	dir      string
	decoys   []*Decoy
	atimeOK  bool
	atimeWhy string
}

// decoyFiles are the places a credential actually lives, and plausible
// contents for each.
//
// Plausible matters: something grepping for "BEGIN OPENSSH PRIVATE KEY"
// or "aws_secret_access_key" should find what it is looking for, or the
// decoy tests nothing. The marker is embedded where the secret would be.
var decoyFiles = []struct {
	name     string
	template string
}{
	{".ssh/id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\n%s\n-----END OPENSSH PRIVATE KEY-----\n"},
	{".aws/credentials", "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = %s\n"},
	{".env", "DATABASE_URL=postgres://user:%s@localhost:5432/app\n"},
	{".netrc", "machine api.example.com login passmcp password %s\n"},
}

// Seed builds a scratch home under root and plants the decoys.
func Seed(root string) (*Canary, error) {
	dir, err := os.MkdirTemp(root, "passmcp-home-")
	if err != nil {
		return nil, fmt.Errorf("canary: scratch home: %w", err)
	}
	c := &Canary{dir: dir}
	decoys, err := plant(dir)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	c.decoys = decoys
	c.atimeOK, c.atimeWhy = measureAtime(dir)
	return c, nil
}

// plant writes the decoys into dir and backdates them.
//
// Separate from Seed so its failures can be exercised against a directory
// that refuses to be written to, which is the state a reader most wants
// this to handle well: planting half the decoys and reporting success
// would mean a run that watched three files and said it watched four.
func plant(dir string) ([]*Decoy, error) {
	var out []*Decoy
	for _, f := range decoyFiles {
		marker, err := newMarker()
		if err != nil {
			return nil, err
		}
		path := filepath.Join(dir, filepath.FromSlash(f.name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("canary: %w", err)
		}
		// 0600, because a credential file that is not is a finding of its
		// own and would make the decoy conspicuous.
		if err := os.WriteFile(path, []byte(fmt.Sprintf(f.template, marker)), 0o600); err != nil {
			return nil, fmt.Errorf("canary: %w", err)
		}
		past := time.Now().Add(-backdate)
		if err := os.Chtimes(path, past, past); err != nil {
			return nil, fmt.Errorf("canary: backdate %s: %w", f.name, err)
		}
		out = append(out, &Decoy{Name: f.name, Path: path, Marker: marker, seeded: past})
	}
	return out, nil
}

// newMarker returns a string that appears nowhere else.
func newMarker() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("canary: marker: %w", err)
	}
	// A recognisable prefix, so a marker turning up in somebody's logs a
	// week later can be traced back to a passmcp run rather than filed as a
	// mystery credential.
	return "passmcp-canary-" + hex.EncodeToString(b), nil
}

// measureAtime finds out whether reading a file here moves its access
// time, by doing exactly that to a file nothing else will touch.
func measureAtime(dir string) (bool, string) {
	probe := filepath.Join(dir, ".passmcp-atime-probe")
	if err := os.WriteFile(probe, []byte("probe"), 0o600); err != nil {
		return false, "could not write a probe file: " + err.Error()
	}
	past := time.Now().Add(-backdate)
	if err := os.Chtimes(probe, past, past); err != nil {
		return false, "could not backdate a probe file: " + err.Error()
	}
	before, ok := accessTime(probe)
	if !ok {
		return false, "this platform does not expose file access times to passmcp"
	}
	f, err := os.Open(probe) //nolint:gosec // a file passmcp just wrote, to measure the filesystem
	if err != nil {
		return false, "could not read a probe file: " + err.Error()
	}
	buf := make([]byte, 8)
	_, _ = f.Read(buf)
	_ = f.Close()

	after, ok := accessTime(probe)
	if !ok {
		return false, "this platform does not expose file access times to passmcp"
	}
	if !after.After(before) {
		return false, "this filesystem does not update access times on read " +
			"(noatime, or a platform that does not track them), so a decoy being opened leaves no trace passmcp can see"
	}
	return true, ""
}

// Env is what to put in the child's environment so it looks here.
func (c *Canary) Env() []string {
	return []string{
		"HOME=" + c.dir,
		// Windows, and the variable a surprising number of cross-platform
		// libraries consult first.
		"USERPROFILE=" + c.dir,
	}
}

// Dir is the scratch home.
func (c *Canary) Dir() string { return c.dir }

// AtimeUsable reports whether the read witness works here, and why not
// when it does not.
func (c *Canary) AtimeUsable() (bool, string) { return c.atimeOK, c.atimeWhy }

// Markers are the strings planted in the decoys.
func (c *Canary) Markers() []string {
	out := make([]string, 0, len(c.decoys))
	for _, d := range c.decoys {
		out = append(out, d.Marker)
	}
	return out
}

// MarkerName maps a marker back to the file it came from.
func (c *Canary) MarkerName(marker string) string {
	for _, d := range c.decoys {
		if d.Marker == marker {
			return d.Name
		}
	}
	return ""
}

// Opened returns the decoys whose access time moved.
//
// Always empty when access times do not work here, which is why every
// caller has to ask AtimeUsable first: an empty list means "none were
// read" only when the instrument was capable of saying otherwise.
func (c *Canary) Opened() []Decoy {
	var out []Decoy
	if !c.atimeOK {
		return nil
	}
	for _, d := range c.decoys {
		at, ok := accessTime(d.Path)
		if ok && at.After(d.seeded) {
			d.Read = true
			out = append(out, *d)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// FindMarkers reports which decoys' markers appear in s, by file name.
func (c *Canary) FindMarkers(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, d := range c.decoys {
		if strings.Contains(s, d.Marker) {
			out = append(out, d.Name)
		}
	}
	sort.Strings(out)
	return out
}

// Close removes the scratch home.
func (c *Canary) Close() error {
	if c.dir == "" {
		return nil
	}
	return os.RemoveAll(c.dir)
}
