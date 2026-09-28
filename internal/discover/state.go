// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package discover

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// State is what a discovery run remembers for the next one: every endpoint
// it has ever proved, with when it was first and last seen.
type State struct {
	Version   int                   `json:"version"`
	Endpoints map[string]StateEntry `json:"endpoints"`
}

// StateEntry is one remembered endpoint.
type StateEntry struct {
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Sources   []Source  `json:"sources"`
	Server    string    `json:"server,omitempty"`
}

// stateVersion is the state file's format version.
const stateVersion = 1

// LoadState reads a state file; a missing file is an empty state, which is
// what a first run starts from.
func LoadState(path string) (*State, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the operator named the file
	if errors.Is(err, fs.ErrNotExist) {
		return &State{Version: stateVersion, Endpoints: map[string]StateEntry{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s is not a discovery state file: %w", path, err)
	}
	if s.Version != stateVersion {
		return nil, fmt.Errorf("%s is state format %d; this passmcp reads %d", path, s.Version, stateVersion)
	}
	if s.Endpoints == nil {
		s.Endpoints = map[string]StateEntry{}
	}
	return &s, nil
}

// Save writes the state, through a temporary file so an interrupted write
// never leaves half a file for the next run to misread.
func (s *State) Save(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Clean(path))
}

// Compare marks each endpoint new or seen, lists the remembered endpoints
// this run no longer found, and updates the state.
//
// An endpoint counts as disappeared only if this run probed its host. A run
// with a different target list says nothing about hosts it never asked, so
// those entries are left as they were rather than reported gone.
func (s *State) Compare(res *Result) {
	probed := map[string]bool{}
	for _, t := range res.Targets {
		if u, err := url.Parse(t.URL); err == nil {
			probed[hostKey(u)] = true
		}
	}
	found := map[string]bool{}
	for i := range res.Endpoints {
		e := &res.Endpoints[i]
		found[e.URL] = true
		prev, ok := s.Endpoints[e.URL]
		if ok {
			e.Status, e.FirstSeen = StatusSeen, prev.FirstSeen
		}
		s.Endpoints[e.URL] = StateEntry{FirstSeen: e.FirstSeen, LastSeen: e.LastSeen, Sources: e.Sources, Server: e.Server}
	}
	var gone []Endpoint
	for u, prev := range s.Endpoints {
		pu, err := url.Parse(u)
		if err != nil || found[u] || !probed[hostKey(pu)] {
			continue
		}
		gone = append(gone, Endpoint{
			URL: u, Sources: prev.Sources, Server: prev.Server,
			Status: StatusDisappeared, FirstSeen: prev.FirstSeen, LastSeen: prev.LastSeen,
		})
	}
	sort.Slice(gone, func(i, j int) bool { return gone[i].URL < gone[j].URL })
	res.Disappeared = gone
}
