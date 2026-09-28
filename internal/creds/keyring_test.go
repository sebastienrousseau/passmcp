// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package creds

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeKeyring is an in-memory backend. Tests use it rather than the
// machine's real credential store, which they must never write to.
type fakeKeyring struct {
	name      string
	available bool
	items     map[string]string
	setErr    error
	getErr    error
}

func newFake() *fakeKeyring {
	return &fakeKeyring{name: "fake", available: true, items: map[string]string{}}
}

func (f *fakeKeyring) Name() string    { return f.name }
func (f *fakeKeyring) Available() bool { return f.available }

func (f *fakeKeyring) Get(key string) (string, error) {
	if f.getErr != nil {
		return "", f.getErr
	}
	v, ok := f.items[key]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

func (f *fakeKeyring) Set(key, secret string) error {
	if f.setErr != nil {
		return f.setErr
	}
	f.items[key] = secret
	return nil
}

func (f *fakeKeyring) Delete(key string) error {
	delete(f.items, key)
	return nil
}

func keyringStore(t *testing.T, k Keyring) *Store {
	t.Helper()
	return &Store{Path: filepath.Join(t.TempDir(), "tokens.json"), Keyring: k}
}

// With a keyring available, the JSON file must hold no secret at all: only
// a marker saying where the real value lives.
func TestKeyringKeepsSecretsOutOfTheFile(t *testing.T) {
	fake := newFake()
	s := keyringStore(t, fake)

	in := StoredToken{
		Endpoint: "https://mcp.example.com/mcp", AccessToken: "at-secret-value",
		RefreshToken: "rt-secret-value", ClientSecret: "cs-secret-value",
		ClientID: "public-client-id", TokenURL: "https://as.example/token",
	}
	if err := s.Put(in); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"at-secret-value", "rt-secret-value", "cs-secret-value"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the token file still holds %q:\n%s", secret, raw)
		}
	}
	if !strings.Contains(string(raw), keyringMarker) {
		t.Errorf("the file should record where the secrets went:\n%s", raw)
	}
	// Non-secret fields stay readable, so the file is still useful to a human.
	if !strings.Contains(string(raw), "public-client-id") {
		t.Errorf("the client id is not a secret and should stay: %s", raw)
	}

	got, err := s.Get(in.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "at-secret-value" || got.RefreshToken != "rt-secret-value" || got.ClientSecret != "cs-secret-value" {
		t.Errorf("secrets did not come back: %+v", got)
	}
	if got.ClientID != "public-client-id" {
		t.Errorf("client id = %q", got.ClientID)
	}
	if b := s.Backend(); b != "fake" {
		t.Errorf("Backend() = %q", b)
	}
}

// Deleting an endpoint must take its secrets out of the keyring too, not
// just drop the file entry and leave them behind.
func TestKeyringDeleteRemovesSecrets(t *testing.T) {
	fake := newFake()
	s := keyringStore(t, fake)
	if err := s.Put(StoredToken{Endpoint: "https://a/mcp", AccessToken: "a", RefreshToken: "r"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(StoredToken{Endpoint: "https://b/mcp", AccessToken: "b"}); err != nil {
		t.Fatal(err)
	}
	if len(fake.items) != 3 {
		t.Fatalf("keyring holds %d items, want 3: %v", len(fake.items), fake.items)
	}
	if err := s.Delete("https://a/mcp"); err != nil {
		t.Fatal(err)
	}
	for k := range fake.items {
		if strings.HasPrefix(k, "https://a/mcp#") {
			t.Errorf("a deleted endpoint left %q behind in the keyring", k)
		}
	}
	if len(fake.items) != 1 {
		t.Errorf("the other endpoint's secret was disturbed: %v", fake.items)
	}
}

// A file written on a machine with a keyring, read on one without, must say
// so rather than hand back a marker as if it were a token.
func TestKeyringUnavailableIsAnExplicitError(t *testing.T) {
	fake := newFake()
	s := keyringStore(t, fake)
	if err := s.Put(StoredToken{Endpoint: "https://a/mcp", AccessToken: "secret"}); err != nil {
		t.Fatal(err)
	}
	// Same file, no keyring.
	gone := &Store{Path: s.Path, Keyring: &fakeKeyring{name: "fake", available: false}}
	_, err := gone.Get("https://a/mcp")
	if err == nil {
		t.Fatal("a marker must not be returned as if it were the token")
	}
	if !strings.Contains(err.Error(), "passmcp login") {
		t.Errorf("the error should say how to recover: %v", err)
	}
	// A keyring that is present but has lost the entry says so too.
	empty := &Store{Path: s.Path, Keyring: newFake()}
	if _, err := empty.Get("https://a/mcp"); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Errorf("a missing entry should be named as such: %v", err)
	}
}

// A keyring that refuses to store must fail the Put, not silently leave the
// secret in the file.
func TestKeyringWriteFailureIsReported(t *testing.T) {
	fake := newFake()
	fake.setErr = errors.New("keychain locked")
	s := keyringStore(t, fake)
	err := s.Put(StoredToken{Endpoint: "https://a/mcp", AccessToken: "secret"})
	if err == nil {
		t.Fatal("a keyring that cannot store must fail the write")
	}
	if !strings.Contains(err.Error(), "keychain locked") {
		t.Errorf("the cause should survive: %v", err)
	}
	if b, err := os.ReadFile(s.Path); err == nil && strings.Contains(string(b), "secret") {
		t.Errorf("the secret must not have been written to the file instead: %s", b)
	}
}

// With no keyring the store behaves exactly as before: secrets in the file,
// 0600, and readable back.
func TestNoKeyringFallsBackToFile(t *testing.T) {
	s := &Store{Path: filepath.Join(t.TempDir(), "tokens.json"), Keyring: &fakeKeyring{name: "none", available: false}}
	if err := s.Put(StoredToken{Endpoint: "https://a/mcp", AccessToken: "plain-secret"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("https://a/mcp")
	if err != nil || got.AccessToken != "plain-secret" {
		t.Fatalf("file fallback: %+v %v", got, err)
	}
	if s.Backend() != "file" {
		t.Errorf("Backend() = %q", s.Backend())
	}
	raw, _ := os.ReadFile(s.Path)
	var all map[string]StoredToken
	if err := json.Unmarshal(raw, &all); err != nil {
		t.Fatal(err)
	}
	if all["https://a/mcp"].AccessToken != "plain-secret" {
		t.Error("the file store should hold the value itself")
	}
}

// Encoding must survive any secret an operator could be handed, including
// the ones that would otherwise break a shell-quoted argument.
func TestSecretEncodingRoundTrip(t *testing.T) {
	for _, v := range []string{
		"", "plain", `has "quotes"`, "has\nnewline", `back\slash`,
		"世界", "with spaces", "$(echo pwned)", "`backtick`", "semi;colon",
		strings.Repeat("x", 8192),
	} {
		enc := encodeSecret(v)
		for _, bad := range []string{`"`, "\n", `\`, "$", "`", ";"} {
			if strings.Contains(enc, bad) {
				t.Errorf("encodeSecret(%q) = %q contains %q, which could break out of a quoted argument", v, enc, bad)
			}
		}
		got, err := decodeSecret(enc)
		if err != nil || got != v {
			t.Errorf("round trip %q: %q %v", v, got, err)
		}
	}
	if _, err := decodeSecret("not valid base64!!!"); err == nil {
		t.Error("a value passmcp did not write must be reported")
	}
}

func TestEncodeKeyIsShellSafe(t *testing.T) {
	for _, v := range []string{`https://a/mcp#access_token`, `https://a/"quoted"#x`, "with space#y"} {
		enc := encodeKey(v)
		for _, bad := range []string{`"`, " ", "\n", `\`} {
			if strings.Contains(enc, bad) {
				t.Errorf("encodeKey(%q) = %q contains %q", v, enc, bad)
			}
		}
	}
}

// The suite must not reach the machine's real credential store.
func TestSelectKeyringIsInertUnderTest(t *testing.T) {
	t.Setenv("PASSMCP_KEYRING", "")
	if k := SelectKeyring(); k != nil {
		t.Fatalf("go test must not select a real keyring, got %q", k.Name())
	}
	t.Setenv("PASSMCP_KEYRING", "file")
	if k := SelectKeyring(); k != nil {
		t.Errorf(`PASSMCP_KEYRING=file must opt out, got %q`, k.Name())
	}
	t.Setenv("PASSMCP_KEYRING", "nonsense")
	if k := SelectKeyring(); k != nil {
		t.Errorf("an unknown backend must not fall through to a real one, got %q", k.Name())
	}
	// Pinning one explicitly still returns it, which is how the opt-in
	// integration test below reaches the real keychain.
	t.Setenv("PASSMCP_KEYRING", "keychain")
	if k := SelectKeyring(); k == nil || k.Name() != "keychain" {
		t.Errorf("an explicit pin must be honoured: %v", k)
	}
}

// TestRealKeyringRoundTrip exercises the machine's actual credential store.
// It is opt-in because it writes there: run it with
//
//	PASSMCP_KEYRING_INTEGRATION=1 go test ./internal/creds/ -run RealKeyring
func TestRealKeyringRoundTrip(t *testing.T) {
	if os.Getenv("PASSMCP_KEYRING_INTEGRATION") == "" {
		t.Skip("set PASSMCP_KEYRING_INTEGRATION=1 to exercise the real credential store")
	}
	// Automatic selection is deliberately inert under test, so name the
	// platform's backend explicitly.
	var k Keyring
	switch runtime.GOOS {
	case "darwin":
		k = &keychain{}
	case "windows":
		k = &wincred{}
	default:
		k = &secretService{}
	}
	if !k.Available() {
		t.Skipf("no %s backend on this machine", k.Name())
	}
	if k.Name() == "wincred" {
		t.Skip("the Windows backend is not implemented yet")
	}
	key := "passmcp-selftest://" + t.Name()
	t.Cleanup(func() { _ = k.Delete(key) })

	const secret = "tok\"en with spaces\nand a newline"
	if err := k.Set(key, secret); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := k.Get(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != secret {
		t.Errorf("round trip: %q != %q", got, secret)
	}
	if err := k.Delete(key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := k.Get(key); !errors.Is(err, ErrNotFound) {
		t.Errorf("after Delete: %v", err)
	}
}

// recordedCall is one invocation a stub runner captured.
type recordedCall struct {
	stdin string
	name  string
	args  []string
}

// stubRunner records what a backend would have executed, and replies with
// what the test tells it to.
func stubRunner(calls *[]recordedCall, stdout string, code int, err error) runner {
	return func(stdin, name string, args ...string) (string, int, error) {
		*calls = append(*calls, recordedCall{stdin: stdin, name: name, args: append([]string(nil), args...)})
		return stdout, code, err
	}
}

// TestKeychainSetKeepsSecretOutOfArgv is the regression for a real bug: the
// first version passed "-w" "-" expecting security to read the password
// from stdin. security has no such convention, so it stored the literal
// string "-" and every token in the keychain was that one character.
//
// The rule the fix has to keep is that the secret reaches the helper on
// stdin, never in argv, where any process running as this user could read
// it off the process table.
func TestKeychainSetKeepsSecretOutOfArgv(t *testing.T) {
	var calls []recordedCall
	k := &keychain{path: "/usr/bin/security", run: stubRunner(&calls, "", 0, nil)}

	const secret = "super-secret-token"
	if err := k.Set("https://a/mcp#access_token", secret); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 {
		t.Fatalf("calls = %d", len(calls))
	}
	got := calls[0]

	for _, a := range got.args {
		if strings.Contains(a, secret) || strings.Contains(a, encodeSecret(secret)) {
			t.Errorf("the secret reached argv: %v", got.args)
		}
		if a == "-" {
			t.Errorf(`the "-" stdin convention does not exist for security: %v`, got.args)
		}
	}
	if got.stdin == "" {
		t.Fatal("the secret must be delivered on stdin")
	}
	if !strings.Contains(got.stdin, encodeSecret(secret)) {
		t.Errorf("stdin does not carry the encoded secret: %q", got.stdin)
	}
	// -i is what makes security read a command from stdin at all.
	if len(got.args) != 1 || got.args[0] != "-i" {
		t.Errorf("args = %v, want exactly [-i]", got.args)
	}
	if !strings.HasPrefix(got.stdin, "add-generic-password -U -s "+service+" ") {
		t.Errorf("unexpected command: %q", got.stdin)
	}
}

func TestKeychainGetDecodes(t *testing.T) {
	var calls []recordedCall
	k := &keychain{path: "/usr/bin/security", run: stubRunner(&calls, encodeSecret("the-token")+"\n", 0, nil)}
	got, err := k.Get("https://a/mcp#access_token")
	if err != nil {
		t.Fatal(err)
	}
	if got != "the-token" {
		t.Errorf("Get = %q", got)
	}
	if calls[0].args[0] != "find-generic-password" {
		t.Errorf("args = %v", calls[0].args)
	}
	// A non-zero exit is "not stored here", not a failure.
	k2 := &keychain{path: "/usr/bin/security", run: stubRunner(&calls, "", 44, nil)}
	if _, err := k2.Get("x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a missing entry must be ErrNotFound, got %v", err)
	}
	// A helper that cannot run at all is an error, not a missing entry.
	k3 := &keychain{path: "/usr/bin/security", run: stubRunner(&calls, "", -1, errors.New("boom"))}
	if _, err := k3.Get("x"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("a broken helper must not look like a missing entry: %v", err)
	}
	// A non-zero exit on Set is reported.
	k4 := &keychain{path: "/usr/bin/security", run: stubRunner(&calls, "", 1, nil)}
	if err := k4.Set("x", "y"); err == nil {
		t.Error("a refused write must be reported")
	}
	if err := k4.Delete("x"); err != nil {
		t.Errorf("Delete: %v", err)
	}
}

func TestSecretServiceCommands(t *testing.T) {
	var calls []recordedCall
	s := &secretService{path: "/usr/bin/secret-tool", run: stubRunner(&calls, "", 0, nil)}

	const secret = "rt-value"
	if err := s.Set("https://a/mcp#refresh_token", secret); err != nil {
		t.Fatal(err)
	}
	got := calls[0]
	// secret-tool reads the secret from stdin natively.
	if got.stdin != encodeSecret(secret) {
		t.Errorf("stdin = %q", got.stdin)
	}
	for _, a := range got.args {
		if strings.Contains(a, secret) {
			t.Errorf("the secret reached argv: %v", got.args)
		}
	}
	if got.args[0] != "store" {
		t.Errorf("args = %v", got.args)
	}

	calls = nil
	s2 := &secretService{path: "/usr/bin/secret-tool", run: stubRunner(&calls, encodeSecret("back")+"\n", 0, nil)}
	v, err := s2.Get("https://a/mcp#refresh_token")
	if err != nil || v != "back" {
		t.Errorf("Get = %q %v", v, err)
	}
	// An empty answer means nothing is stored.
	s3 := &secretService{path: "/usr/bin/secret-tool", run: stubRunner(&calls, "", 0, nil)}
	if _, err := s3.Get("x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("empty output must be ErrNotFound: %v", err)
	}
	if err := s2.Delete("x"); err != nil {
		t.Errorf("Delete: %v", err)
	}
	// A refused write is reported.
	s4 := &secretService{path: "/usr/bin/secret-tool", run: stubRunner(&calls, "", 1, nil)}
	if err := s4.Set("x", "y"); err == nil {
		t.Error("a refused write must be reported")
	}
}

// The account name is attacker-influenced in the sense that it contains an
// endpoint URL the operator typed. It must not be able to change the shape
// of the command.
func TestKeyNeverEscapesTheCommand(t *testing.T) {
	var calls []recordedCall
	k := &keychain{path: "/usr/bin/security", run: stubRunner(&calls, "", 0, nil)}
	nasty := `https://a/mcp" -s other -a "pwned#access_token`
	if err := k.Set(nasty, "s"); err != nil {
		t.Fatal(err)
	}
	cmd := calls[0].stdin
	if strings.Count(cmd, `"`) != 4 {
		t.Errorf("the key changed the command's quoting: %q", cmd)
	}
	if strings.Contains(cmd, "-s other") {
		t.Errorf("the key injected a flag: %q", cmd)
	}
}

func TestWincredIsHonestAboutBeingUnimplemented(t *testing.T) {
	w := &wincred{}
	if _, err := w.Get("x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get: %v", err)
	}
	if err := w.Set("x", "y"); err == nil {
		t.Error("Set must not silently claim success")
	}
	if err := w.Delete("x"); err != nil {
		t.Errorf("Delete: %v", err)
	}
	if w.Name() != "wincred" {
		t.Errorf("Name = %q", w.Name())
	}
	_ = w.Available()
}

// execRun is the only part that actually launches a process. Exercise it
// against shell utilities rather than a credential store, so the timeout,
// exit-code and stdin plumbing are covered without touching a keychain.
func TestExecRun(t *testing.T) {
	if _, err := os.Stat("/bin/cat"); err != nil {
		t.Skip("no /bin/cat on this machine")
	}
	out, code, err := execRun("hello", "/bin/cat")
	if err != nil || code != 0 || out != "hello" {
		t.Errorf("cat: %q %d %v", out, code, err)
	}
	// A non-zero exit is reported as a code, not an error: "not found" is a
	// normal answer from a credential store.
	if _, code, err := execRun("", "/bin/sh", "-c", "exit 7"); err != nil || code != 7 {
		t.Errorf("exit 7: code=%d err=%v", code, err)
	}
	// A binary that does not exist is an error.
	if _, _, err := execRun("", "/nonexistent/helper-binary"); err == nil {
		t.Error("a missing helper must be an error")
	}
}

// Availability must not depend on the machine the suite runs on.
func TestBackendAvailability(t *testing.T) {
	// A stubbed runner marks a backend usable regardless of platform, which
	// is what lets the command tests above run everywhere.
	if !(&keychain{run: func(string, string, ...string) (string, int, error) { return "", 0, nil }}).Available() {
		t.Error("a stubbed keychain is available")
	}
	if !(&secretService{run: func(string, string, ...string) (string, int, error) { return "", 0, nil }}).Available() {
		t.Error("a stubbed secret service is available")
	}
	// Without a helper path, neither is.
	if (&keychain{}).Available() && runtime.GOOS != "darwin" {
		t.Error("keychain must not claim availability off darwin")
	}
	if (&secretService{}).Available() && runtime.GOOS == "darwin" {
		t.Error("secret-service must not claim availability on darwin")
	}
	if (&wincred{}).Available() && runtime.GOOS != "windows" {
		t.Error("wincred must not claim availability off windows")
	}
	// Both fall back to the real runner when nothing is stubbed.
	if (&keychain{}).exec() == nil || (&secretService{}).exec() == nil {
		t.Error("exec() must always return a runner")
	}
}

// Every named backend can be pinned, on any platform.
func TestSelectKeyringPins(t *testing.T) {
	for _, name := range []string{"keychain", "secret-service", "wincred"} {
		t.Setenv("PASSMCP_KEYRING", name)
		k := SelectKeyring()
		if k == nil || k.Name() != name {
			t.Errorf("PASSMCP_KEYRING=%s selected %v", name, k)
		}
	}
	t.Setenv("PASSMCP_KEYRING", "  KeyChain  ")
	if k := SelectKeyring(); k == nil || k.Name() != "keychain" {
		t.Errorf("the value should be trimmed and case-folded: %v", k)
	}
	// "auto" under test picks nothing, so the suite never reaches a real store.
	t.Setenv("PASSMCP_KEYRING", "auto")
	if k := SelectKeyring(); k != nil {
		t.Errorf("auto under test must select nothing, got %q", k.Name())
	}
}
