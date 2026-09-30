// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package creds

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"satellion.com/passmcp/auth"
)

// StoredToken is what `passmcp login` persists so later runs can resume the
// authorization-code flow without a browser.
type StoredToken struct {
	Endpoint     string    `json:"endpoint"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
	TokenURL     string    `json:"token_url"`
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret,omitempty"`
	Resource     string    `json:"resource,omitempty"`
	Issuer       string    `json:"issuer,omitempty"`
	SavedAt      time.Time `json:"saved_at"`
}

// Store is the on-disk token store, one entry per endpoint.
//
// Entries hold refresh tokens and, for dynamically registered clients,
// client secrets. The file is created 0600 (on Windows, with an
// access-control list granting only the current user) and a store that
// anyone else can read is refused rather than used: a long-lived refresh
// token is worth as much as a password.
type Store struct {
	Path string
	// Keyring, when non-nil, holds the secret fields; the JSON file then
	// keeps only the non-secret record and a marker. When nil, the store
	// selects one automatically, and falls back to the file when the
	// machine offers none.
	Keyring Keyring

	mu       sync.Mutex
	krOnce   sync.Once
	resolved Keyring
}

// keyringMarker replaces a secret in the JSON file when the real value
// lives in the OS keychain.
const keyringMarker = "keyring:"

// keyring resolves the backend once per store.
func (s *Store) keyring() Keyring {
	s.krOnce.Do(func() {
		if s.Keyring != nil {
			s.resolved = s.Keyring
			return
		}
		s.resolved = SelectKeyring()
	})
	return s.resolved
}

// Backend names where secrets are kept, for the operator and the report.
func (s *Store) Backend() string {
	if k := s.keyring(); k != nil && k.Available() {
		return k.Name()
	}
	return "file"
}

// secretKey is the keychain account name for one endpoint and field.
func secretKey(endpoint, field string) string { return endpoint + "#" + field }

// split moves the secret fields of t into the keyring, leaving markers
// behind. It returns t unchanged when there is no keyring to use.
func (s *Store) split(t StoredToken) (StoredToken, error) {
	k := s.keyring()
	if k == nil || !k.Available() {
		return t, nil
	}
	fields := []struct {
		name string
		val  *string
	}{
		{"access_token", &t.AccessToken},
		{"refresh_token", &t.RefreshToken},
		{"client_secret", &t.ClientSecret},
	}
	for _, f := range fields {
		if *f.val == "" || strings.HasPrefix(*f.val, keyringMarker) {
			continue
		}
		if err := k.Set(secretKey(t.Endpoint, f.name), *f.val); err != nil {
			return t, fmt.Errorf("creds: storing %s in the %s keyring: %w", f.name, k.Name(), err)
		}
		*f.val = keyringMarker + k.Name()
	}
	return t, nil
}

// join puts the secrets back, reading each from the keyring when the file
// holds a marker rather than a value.
func (s *Store) join(t *StoredToken) error {
	k := s.keyring()
	fields := []struct {
		name string
		val  *string
	}{
		{"access_token", &t.AccessToken},
		{"refresh_token", &t.RefreshToken},
		{"client_secret", &t.ClientSecret},
	}
	for _, f := range fields {
		if !strings.HasPrefix(*f.val, keyringMarker) {
			continue
		}
		if k == nil || !k.Available() {
			return fmt.Errorf("creds: %s for %s is held in the %s keyring, which is not available here; run `passmcp login %s` again", f.name, t.Endpoint, strings.TrimPrefix(*f.val, keyringMarker), t.Endpoint)
		}
		secret, err := k.Get(secretKey(t.Endpoint, f.name))
		if errors.Is(err, ErrNotFound) {
			return fmt.Errorf("creds: %s for %s is missing from the %s keyring; run `passmcp login %s` again", f.name, t.Endpoint, k.Name(), t.Endpoint)
		}
		if err != nil {
			return fmt.Errorf("creds: reading %s from the %s keyring: %w", f.name, k.Name(), err)
		}
		*f.val = secret
	}
	return nil
}

// purge removes an endpoint's secrets from the keyring.
func (s *Store) purge(endpoint string) {
	k := s.keyring()
	if k == nil || !k.Available() {
		return
	}
	for _, f := range []string{"access_token", "refresh_token", "client_secret"} {
		_ = k.Delete(secretKey(endpoint, f))
	}
}

// ErrInsecurePermissions reports a token store other users can read.
type ErrInsecurePermissions struct {
	Path string
	// Mode is the file's mode, on Unix, where the mode is the check.
	Mode os.FileMode
	// Reason says what is wrong when the check is not a mode, as on
	// Windows, where it is the file's access-control list.
	Reason string
}

func (e *ErrInsecurePermissions) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("token store %s %s; it holds refresh tokens and must be readable only by you "+
			"(icacls \"%s\" /inheritance:r /grant:r \"%%USERNAME%%:F\", or delete it and run passmcp login again)", e.Path, e.Reason, e.Path)
	}
	return fmt.Sprintf("token store %s is mode %#o; it holds refresh tokens and must not be readable by other users (chmod 600 %s)", e.Path, e.Mode.Perm(), e.Path)
}

// DefaultStorePath is $XDG_CONFIG_HOME/passmcp/tokens.json.
func DefaultStorePath() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "passmcp", "tokens.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".config", "passmcp", "tokens.json")
	}
	return filepath.Join(home, ".config", "passmcp", "tokens.json")
}

func (s *Store) path() string {
	if s.Path != "" {
		return s.Path
	}
	return DefaultStorePath()
}

func (s *Store) load() (map[string]StoredToken, error) {
	p := s.path()
	info, err := os.Stat(p)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return map[string]StoredToken{}, nil
	case err != nil:
		return nil, err
	}
	if err := checkStoreAccess(p, info); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p) // #nosec G304 -- the path is the operator's own store
	if errors.Is(err, os.ErrNotExist) {
		return map[string]StoredToken{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]StoredToken{}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("token store %s: %w", s.path(), err)
	}
	return out, nil
}

// Get returns the stored token for endpoint, if any.
func (s *Store) Get(endpoint string) (*StoredToken, error) {
	all, err := s.load()
	if err != nil {
		return nil, err
	}
	t, ok := all[endpoint]
	if !ok {
		return nil, nil
	}
	if err := s.join(&t); err != nil {
		return nil, err
	}
	return &t, nil
}

// Put saves a token, creating the store with 0600 permissions.
func (s *Store) Put(t StoredToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.load()
	if err != nil {
		return err
	}
	t.SavedAt = time.Now()
	split, err := s.split(t)
	if err != nil {
		return err
	}
	all[t.Endpoint] = split
	return s.save(all)
}

// Delete removes the entry for endpoint.
func (s *Store) Delete(endpoint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.load()
	if err != nil {
		return err
	}
	delete(all, endpoint)
	s.purge(endpoint)
	return s.save(all)
}

// save writes the whole store atomically: a crash between truncate and
// write would otherwise lose every other endpoint's token, not just the one
// being changed.
func (s *Store) save(all map[string]StoredToken) error {
	p := s.path()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	// #nosec G117 -- persisting the token is this file's whole purpose; it is
	// written 0600 and refused if the mode ever widens.
	b, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p), ".tokens-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		_ = f.Close()
		_ = os.Remove(tmp) // no-op once the rename succeeded
	}()
	if err := restrictFile(f); err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Source builds a refreshing token source from a stored token.
func (t *StoredToken) Source(hc httpClient) auth.TokenSource {
	tok := &auth.Token{AccessToken: t.AccessToken, RefreshToken: t.RefreshToken, TokenType: t.TokenType, Scope: t.Scope, Expiry: t.Expiry}
	return auth.NewRefreshingSource(hc.client(), auth.Endpoint{TokenURL: t.TokenURL}, auth.Credentials{ClientID: t.ClientID, ClientSecret: t.ClientSecret}, t.Resource, tok)
}
