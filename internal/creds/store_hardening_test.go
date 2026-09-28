// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package creds

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func tempStore(t *testing.T) *Store {
	t.Helper()
	return &Store{Path: filepath.Join(t.TempDir(), "sub", "tokens.json")}
}

// The store holds refresh tokens and client secrets. One that other users
// can read is refused rather than used: reading it would be treating a
// password-equivalent as if the filesystem had vouched for it.
func TestStoreRefusesWorldReadableFile(t *testing.T) {
	s := tempStore(t)
	if err := s.Put(StoredToken{Endpoint: "https://a/mcp", AccessToken: "t"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); runtime.GOOS != "windows" && perm != 0o600 {
		t.Errorf("new store is mode %#o, want 0600", perm)
	}
	if runtime.GOOS == "windows" {
		// The rest of this test widens the mode and expects the store to
		// refuse it. Windows has no mode to widen — chmod there only
		// toggles the read-only attribute — so the refusal cannot be
		// provoked, and insecureMode is a no-op by design.
		return
	}

	if err := os.Chmod(s.Path, 0o644); err != nil {
		t.Fatal(err)
	}
	var insecure *ErrInsecurePermissions
	if _, err := s.Get("https://a/mcp"); !errors.As(err, &insecure) {
		t.Fatalf("a readable store must be refused, got %v", err)
	}
	if insecure.Error() == "" {
		t.Error("the error must tell the operator how to fix it")
	}
	// Group-only access is just as bad.
	if err := os.Chmod(s.Path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("https://a/mcp"); !errors.As(err, &insecure) {
		t.Error("group-readable must also be refused")
	}
}

// Delete used to truncate and rewrite in place, so a crash mid-write lost
// every other endpoint's token rather than the one being removed.
func TestDeleteIsAtomicAndKeepsOthers(t *testing.T) {
	s := tempStore(t)
	for _, ep := range []string{"https://a/mcp", "https://b/mcp", "https://c/mcp"} {
		if err := s.Put(StoredToken{Endpoint: ep, AccessToken: "t-" + ep, RefreshToken: "r"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Delete("https://b/mcp"); err != nil {
		t.Fatal(err)
	}
	for _, ep := range []string{"https://a/mcp", "https://c/mcp"} {
		got, err := s.Get(ep)
		if err != nil || got == nil {
			t.Fatalf("Delete lost %s: %v", ep, err)
		}
	}
	if got, _ := s.Get("https://b/mcp"); got != nil {
		t.Error("the deleted entry is still present")
	}
	info, err := os.Stat(s.Path)
	if err != nil {
		t.Fatalf("Delete lost the store: %v", err)
	}
	// Windows synthesises this mode; there is nothing to preserve there.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("Delete must preserve 0600, got %#o", info.Mode().Perm())
	}
	// No temporary file may be left behind holding secrets.
	entries, err := os.ReadDir(filepath.Dir(s.Path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(s.Path) {
			t.Errorf("stray file left in the store directory: %s", e.Name())
		}
	}
}

// Two logins racing must not lose one another's token.
func TestConcurrentPutKeepsEveryToken(t *testing.T) {
	s := tempStore(t)
	var wg sync.WaitGroup
	endpoints := []string{"https://a/mcp", "https://b/mcp", "https://c/mcp", "https://d/mcp", "https://e/mcp"}
	for _, ep := range endpoints {
		wg.Add(1)
		go func(ep string) {
			defer wg.Done()
			if err := s.Put(StoredToken{Endpoint: ep, AccessToken: "t"}); err != nil {
				t.Errorf("Put(%s): %v", ep, err)
			}
		}(ep)
	}
	wg.Wait()
	b, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	var all map[string]StoredToken
	if err := json.Unmarshal(b, &all); err != nil {
		t.Fatalf("store is not valid JSON after concurrent writes: %v", err)
	}
	if len(all) != len(endpoints) {
		t.Errorf("kept %d of %d tokens", len(all), len(endpoints))
	}
}

func TestStoreMissingFileIsEmpty(t *testing.T) {
	s := tempStore(t)
	got, err := s.Get("https://nope/mcp")
	if err != nil || got != nil {
		t.Errorf("a missing store is empty, not an error: %v %v", got, err)
	}
	if err := s.Delete("https://nope/mcp"); err != nil {
		t.Errorf("deleting from a missing store: %v", err)
	}
}
