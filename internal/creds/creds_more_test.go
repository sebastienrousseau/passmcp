// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package creds

import (
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"satellion.com/passmcp"
)

func TestSetIgnoresEmptyAndBasicSplit(t *testing.T) {
	c := &Credentials{}
	c.set("token", "", "flag")
	if c.Sources != nil {
		t.Error("empty value must not record a source")
	}
	c.set("basic", "user", "flag")
	if c.BasicUser != "user" || c.BasicPassword != "" {
		t.Errorf("basic without colon: %+v", c)
	}
	c.set("unknown-field", "v", "flag")
	if c.Sources["unknown-field"] != "flag" {
		t.Error("unknown field still records its source")
	}
	if err := c.SetFromEnvName("token", ""); err != nil {
		t.Error("empty env name is a no-op")
	}
}

func TestValidateMoreBranches(t *testing.T) {
	c := &Credentials{Mode: ""}
	if err := c.Validate(); err != nil {
		t.Errorf("empty mode is auto: %v", err)
	}
	c = &Credentials{Mode: ModeClientCredentials}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "--client-id") {
		t.Errorf("client-credentials without id: %v", err)
	}
	c = &Credentials{Mode: ModeClientCredentials, ClientMetadataURL: "https://c/m.json"}
	if err := c.Validate(); err != nil {
		t.Errorf("cimd suffices: %v", err)
	}
	c = &Credentials{Mode: ModeNone, BasicPassword: "p"}
	if err := c.Validate(); err == nil {
		t.Error("password without user")
	}
	c = &Credentials{Mode: ModeAuthorizationCode}
	if err := c.Validate(); err != nil {
		t.Errorf("authorization-code needs nothing up front: %v", err)
	}
	if (&Credentials{Mode: ModeAuto, ClientMetadataURL: "https://x"}).Effective() != ModeClientCredentials {
		t.Error("cimd implies client-credentials")
	}
}

func TestDescribeQuotesScopeWithSpaces(t *testing.T) {
	c := &Credentials{Mode: ModeBearer, Token: "t", Scope: "a b", Headers: map[string]string{"X-A": "1"}}
	d := c.Describe()
	if !strings.Contains(d, `scope="a b"`) || !strings.Contains(d, "bearer") {
		t.Errorf("describe = %s", d)
	}
	if strconvQuote("plain") != "plain" {
		t.Error("no quoting without spaces")
	}
}

func TestApplyNoneBearerAndRedirectPort(t *testing.T) {
	var cfg passmcp.Config
	(&Credentials{Mode: ModeNone}).Apply(&cfg)
	if cfg.Auth.Mode != passmcp.AuthNone || cfg.Headers != nil {
		t.Errorf("none: %+v", cfg)
	}
	(&Credentials{Mode: ModeBearer, Token: "tok"}).Apply(&cfg)
	if cfg.Auth.Mode != passmcp.AuthBearer || cfg.Auth.Token != "tok" {
		t.Errorf("bearer: %+v", cfg.Auth)
	}
	(&Credentials{Mode: ModeAuthorizationCode, RedirectPort: 9000}).Apply(&cfg)
	if cfg.Auth.RedirectURI != "http://127.0.0.1:9000/callback" {
		t.Errorf("redirect = %s", cfg.Auth.RedirectURI)
	}
	// existing headers map is reused
	cfg = passmcp.Config{Headers: map[string]string{"Keep": "me"}}
	(&Credentials{Mode: ModeNone, Headers: map[string]string{"X": "y"}}).Apply(&cfg)
	if cfg.Headers["Keep"] != "me" || cfg.Headers["X"] != "y" {
		t.Errorf("headers = %v", cfg.Headers)
	}
}

func TestParseParamBadShapes(t *testing.T) {
	if _, _, err := ParseParam("novalue"); err == nil {
		t.Error("missing =")
	}
	if k, v, err := ParseParam("k="); err != nil || k != "k" || v != "" {
		t.Errorf("empty value allowed: %s %s %v", k, v, err)
	}
}

func TestHTTPWrapper(t *testing.T) {
	// A nil client stays nil so the auth package's default, which has a
	// timeout, is used; http.DefaultClient has none.
	if (HTTP{}).client() != nil {
		t.Error("nil client must be passed on as nil, not as http.DefaultClient")
	}
	c := &http.Client{}
	if (HTTP{C: c}).client() != c {
		t.Error("explicit client returned")
	}
}

func TestStorePathsAndErrors(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	if DefaultStorePath() != filepath.Join("/xdg", "passmcp", "tokens.json") {
		t.Errorf("xdg store = %s", DefaultStorePath())
	}
	t.Setenv("XDG_CONFIG_HOME", "")
	home, _ := os.UserHomeDir()
	if DefaultStorePath() != filepath.Join(home, ".config", "passmcp", "tokens.json") {
		t.Errorf("home store = %s", DefaultStorePath())
	}
	t.Setenv("HOME", "")
	if !strings.HasSuffix(DefaultStorePath(), filepath.Join(".config", "passmcp", "tokens.json")) {
		t.Errorf("fallback store = %s", DefaultStorePath())
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	s := &Store{}
	if s.path() != DefaultStorePath() {
		t.Error("empty Path uses default")
	}
	if err := s.Put(StoredToken{Endpoint: "e", AccessToken: "a"}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get("e"); err != nil || got == nil {
		t.Errorf("get after put: %v %v", got, err)
	}

	dir := t.TempDir()
	broken := &Store{Path: filepath.Join(dir, "tokens.json")}
	_ = os.WriteFile(broken.Path, []byte("{broken"), 0o600)
	if _, err := broken.Get("x"); err == nil {
		t.Error("broken store must error on Get")
	}
	if err := broken.Put(StoredToken{Endpoint: "x"}); err == nil {
		t.Error("broken store must error on Put")
	}
	if err := broken.Delete("x"); err == nil {
		t.Error("broken store must error on Delete")
	}
	unreadable := &Store{Path: filepath.Join(dir, "sub")}
	_ = os.Mkdir(unreadable.Path, 0o700)
	if _, err := unreadable.Get("x"); err == nil {
		t.Error("directory as store must error")
	}
	nested := &Store{Path: filepath.Join(dir, "a", "b", "tokens.json")}
	if err := nested.Put(StoredToken{Endpoint: "n"}); err != nil {
		t.Errorf("nested dirs created: %v", err)
	}
	if err := nested.Delete("n"); err != nil {
		t.Error(err)
	}
	// A directory passmcp cannot create the store in. Chmod is the Unix way
	// to arrange that; on Windows it only toggles the read-only attribute
	// and the write still succeeds, so a file standing where the directory
	// needs to be is used instead. Either way Put must report the failure
	// rather than silently dropping the token.
	if runtime.GOOS == "windows" {
		// dir/sub is already a directory above, so the file goes somewhere
		// of its own.
		blocker := filepath.Join(dir, "blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		blocked := &Store{Path: filepath.Join(blocker, "x", "tokens.json")}
		if err := blocked.Put(StoredToken{Endpoint: "b"}); err == nil {
			t.Error("mkdir failure must propagate")
		}
		return
	}
	blocked := &Store{Path: filepath.Join(dir, "sub", "x", "tokens.json")}
	_ = os.Chmod(filepath.Join(dir, "sub"), 0o500)
	defer func() { _ = os.Chmod(filepath.Join(dir, "sub"), 0o700) }()
	if err := blocked.Put(StoredToken{Endpoint: "b"}); err == nil && os.Getuid() != 0 {
		t.Error("mkdir failure must propagate")
	}
}
