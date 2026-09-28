// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package creds

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// Keyring stores a secret outside the process, ideally where the operating
// system can protect it.
//
// A refresh token is password-equivalent: it mints access tokens until it is
// revoked. Holding one in a file that any process running as the user can
// read means a malicious postinstall script or editor extension collects
// every server the operator has ever logged into. The OS keychains exist for
// exactly this, and reaching them through the platform's own command-line
// tool keeps passmcp's dependency list empty — which matters, because a
// credential store is the last place to add transitive dependencies.
type Keyring interface {
	// Name identifies the backend for the operator.
	Name() string
	// Available reports whether this backend can be used on this machine.
	Available() bool
	// Get returns the secret for key, or ErrNotFound.
	Get(key string) (string, error)
	// Set stores secret under key.
	Set(key, secret string) error
	// Delete removes key. Removing a key that is not there is not an error.
	Delete(key string) error
}

// ErrNotFound means the keyring holds no secret for that key.
var ErrNotFound = errors.New("creds: no secret stored under that key")

// service is the keychain service name entries are filed under.
const service = "passmcp-server"

// keyringTimeout bounds a call to an external keychain helper. A prompt the
// operator never answers must not hang the run forever.
const keyringTimeout = 30 * time.Second

// SelectKeyring returns the best available backend for this machine.
//
// PASSMCP_KEYRING pins one: "auto" (the default), "keychain", "secret-service",
// "wincred", or "file" to opt out of the OS store deliberately.
//
// Under `go test` it returns nil unless a backend is pinned explicitly. A
// test suite must not write to the machine's real credential store: the
// entries outlive the run, and an operator who runs the suite should not
// afterwards find test data in their login keychain.
func SelectKeyring() Keyring {
	choice := strings.ToLower(strings.TrimSpace(os.Getenv("PASSMCP_KEYRING")))
	// Automatic selection is suppressed under test. Only an explicitly named
	// backend reaches the machine's real credential store, which is what the
	// opt-in integration test uses.
	if (choice == "" || choice == "auto") && testing.Testing() {
		return nil
	}
	all := []Keyring{&keychain{}, &secretService{}, &wincred{}}
	for _, k := range all {
		if choice == k.Name() {
			return k
		}
	}
	if choice == "file" {
		return nil // the caller falls back to the file store
	}
	if choice != "" && choice != "auto" {
		return nil
	}
	for _, k := range all {
		if k.Available() {
			return k
		}
	}
	return nil
}

// encodeSecret and encodeKey make a value safe to place inside a quoted
// argument of a keychain helper command.
//
// The secret is Base64 so that no value the operator was handed — a token
// containing a quote, a newline, a backslash — can break out of the quoting
// and become part of the command. The account name is percent-encoded for
// the same reason. Both alphabets are plain ASCII with no shell meaning.
func encodeSecret(v string) string { return base64.StdEncoding.EncodeToString([]byte(v)) }

func decodeSecret(v string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
	if err != nil {
		return "", fmt.Errorf("creds: the keyring returned a value passmcp did not write: %w", err)
	}
	return string(b), nil
}

func encodeKey(v string) string { return url.QueryEscape(v) }

// runner executes a keychain helper. It is a field on each backend so a
// test can assert on the exact command without running anything: the one
// bug this abstraction has already caught was a helper invoked with a flag
// that stored the literal string "-" instead of the secret.
type runner func(stdin, name string, args ...string) (stdout string, code int, err error)

// execRun runs a keychain helper with a bounded lifetime. A prompt the
// operator never answers must not hang the run forever.
func execRun(stdin, name string, args ...string) (string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), keyringTimeout)
	defer cancel()
	// #nosec G204 -- name and args are fixed literals chosen by this file;
	// caller-supplied values are encoded by encodeKey/encodeSecret first.
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ctx.Err() != nil {
		return "", -1, fmt.Errorf("creds: %s did not answer within %s", name, keyringTimeout)
	}
	code := cmd.ProcessState.ExitCode()
	if err != nil && code < 0 {
		return out.String(), code, err
	}
	return out.String(), code, nil
}

// --- macOS -----------------------------------------------------------------

// keychain is the macOS login keychain, reached through /usr/bin/security.
type keychain struct {
	once sync.Once
	path string
	run  runner
}

// Name implements Keyring.
func (k *keychain) Name() string { return "keychain" }

// Available implements Keyring.
func (k *keychain) Available() bool {
	if k.run != nil {
		return true // stubbed for a test
	}
	if runtime.GOOS != "darwin" {
		return false
	}
	k.once.Do(func() { k.path, _ = exec.LookPath("security") })
	return k.path != ""
}

func (k *keychain) exec() runner {
	if k.run != nil {
		return k.run
	}
	return execRun
}

// Get implements Keyring.
func (k *keychain) Get(key string) (string, error) {
	if !k.Available() {
		return "", ErrNotFound
	}
	out, code, err := k.exec()("", k.path, "find-generic-password", "-s", service, "-a", encodeKey(key), "-w")
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", ErrNotFound
	}
	return decodeSecret(out)
}

// Set implements Keyring.
func (k *keychain) Set(key, secret string) error {
	if !k.Available() {
		return errors.New("creds: the macOS keychain is not available")
	}
	// security has no flag that reads a password from stdin, but it does
	// accept whole commands there with -i. Passing the command that way
	// keeps the secret out of the process table, where any process running
	// as this user could read it off the command line.
	cmd := fmt.Sprintf("add-generic-password -U -s %s -a %q -w %q\n", service, encodeKey(key), encodeSecret(secret))
	_, code, err := k.exec()(cmd, k.path, "-i")
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("creds: keychain refused to store the secret (security exited %d)", code)
	}
	return nil
}

// Delete implements Keyring.
func (k *keychain) Delete(key string) error {
	if !k.Available() {
		return nil
	}
	_, _, err := k.exec()("", k.path, "delete-generic-password", "-s", service, "-a", encodeKey(key))
	return err
}

// --- Linux / BSD (freedesktop Secret Service) -------------------------------

// secretService is the freedesktop Secret Service, reached through
// secret-tool.
type secretService struct {
	once sync.Once
	path string
	run  runner
}

// Name implements Keyring.
func (s *secretService) Name() string { return "secret-service" }

// Available implements Keyring.
func (s *secretService) Available() bool {
	if s.run != nil {
		return true // stubbed for a test
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		return false
	}
	s.once.Do(func() { s.path, _ = exec.LookPath("secret-tool") })
	// secret-tool needs a running Secret Service, which needs a session bus.
	if s.path == "" {
		return false
	}
	return os.Getenv("DBUS_SESSION_BUS_ADDRESS") != "" || os.Getenv("XDG_RUNTIME_DIR") != ""
}

func (s *secretService) exec() runner {
	if s.run != nil {
		return s.run
	}
	return execRun
}

// Get implements Keyring.
func (s *secretService) Get(key string) (string, error) {
	if !s.Available() {
		return "", ErrNotFound
	}
	out, code, err := s.exec()("", s.path, "lookup", "service", service, "account", encodeKey(key))
	if err != nil {
		return "", err
	}
	if code != 0 || out == "" {
		return "", ErrNotFound
	}
	return decodeSecret(out)
}

// Set implements Keyring.
func (s *secretService) Set(key, secret string) error {
	if !s.Available() {
		return errors.New("creds: no Secret Service is available")
	}
	// secret-tool reads the secret from stdin, so it never reaches argv.
	_, code, err := s.exec()(encodeSecret(secret), s.path, "store", "--label=passmcp MCP credentials", "service", service, "account", encodeKey(key))
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("creds: the Secret Service refused to store the secret (secret-tool exited %d)", code)
	}
	return nil
}

// Delete implements Keyring.
func (s *secretService) Delete(key string) error {
	if !s.Available() {
		return nil
	}
	_, _, err := s.exec()("", s.path, "clear", "service", service, "account", encodeKey(key))
	return err
}

// --- Windows ---------------------------------------------------------------

// wincred is a placeholder for a Windows credential backend.
type wincred struct {
	once sync.Once
	path string
}

// Name implements Keyring.
func (w *wincred) Name() string { return "wincred" }

// Available implements Keyring.
func (w *wincred) Available() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	w.once.Do(func() { w.path, _ = exec.LookPath("powershell") })
	return w.path != ""
}

// Get implements Keyring. It always reports not-found.
//
// Windows has no first-party command-line credential store that returns a
// secret in plaintext without a PowerShell module passmcp would have to
// require. Rather than pretend, this backend reports that it cannot serve
// the request, so the caller falls back to the file store and says so.
func (w *wincred) Get(string) (string, error) { return "", ErrNotFound }

// Set implements Keyring.
func (w *wincred) Set(string, string) error {
	return errors.New("creds: no Windows credential backend is implemented yet; the file store is used instead")
}

// Delete implements Keyring.
func (w *wincred) Delete(string) error { return nil }
