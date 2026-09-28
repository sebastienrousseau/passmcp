// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package fleet validates a whole set of MCP servers on a schedule and says
// what changed in each since its last signed run.
//
// A one-off check misses staged-trust attacks: the server that passes review
// and widens a tool the following week is the one that gets through, and a
// malicious update can arrive in an ordinary release. `passmcp watch` and
// `--baseline` already catch that for one server; this makes it a fleet
// capability. Every server is checked, an attestation is written for each,
// and each run is compared with that server's previous one — catalogue,
// verdicts and score — so a rug pull is caught within one scheduling
// interval rather than at the next manual review.
//
// It runs on the operator's side, typically as a CronJob, and nothing leaves
// (ADR 0006): the only hosts contacted are the servers the fleet file names
// and the authorization servers they advertise.
package fleet

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Version is the fleet file format this passmcp reads.
const Version = 1

// File is a fleet: the servers to validate, and how.
type File struct {
	Version int `yaml:"version"`
	// State is the directory runs are kept in, relative to the fleet file.
	// The --state flag overrides it.
	State   string   `yaml:"state,omitempty"`
	Pacing  Pacing   `yaml:"pacing,omitempty"`
	Servers []Server `yaml:"servers"`
}

// Pacing bounds how hard each server is exercised.
type Pacing struct {
	RPS         *float64 `yaml:"rps,omitempty"`
	Samples     int      `yaml:"samples,omitempty"`
	Concurrency int      `yaml:"concurrency,omitempty"`
	CallTimeout string   `yaml:"call_timeout,omitempty"`
}

// Server is one server in the fleet.
type Server struct {
	// Name identifies the server in reports and names its directory under
	// the state directory.
	Name string `yaml:"name"`
	// Endpoint is the URL of a remote server.
	Endpoint string `yaml:"endpoint,omitempty"`
	// Command is the program to run for a stdio server.
	Command []string `yaml:"command,omitempty"`
	// Transport is "http" or "stdio". Optional: it follows from which of
	// Endpoint and Command is set, and a value that disagrees is an error.
	Transport string `yaml:"transport,omitempty"`
	// Credential says how to authenticate, by reference only.
	Credential *Credential `yaml:"credential,omitempty"`
	// Policy is an acceptance policy file, relative to the fleet file.
	Policy string `yaml:"policy,omitempty"`
}

// Credential names where a secret lives; it never holds one. A fleet file is
// committed to a repository and mounted into a container, and neither is a
// place a token belongs. A key such as `token:` is refused as unknown.
type Credential struct {
	// Mode is "bearer", "client-credentials" or "none". Empty means bearer
	// when TokenEnv is set and none otherwise.
	Mode            string `yaml:"mode,omitempty"`
	TokenEnv        string `yaml:"token_env,omitempty"`
	ClientID        string `yaml:"client_id,omitempty"`
	ClientSecretEnv string `yaml:"client_secret_env,omitempty"`
	TokenURL        string `yaml:"token_url,omitempty"`
	Scope           string `yaml:"scope,omitempty"`
}

// Load reads and validates a fleet file.
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the operator names their own fleet file
	if err != nil {
		return nil, err
	}
	f, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

// Parse reads a fleet from bytes. Unknown keys are errors, for the reason
// policy files refuse them: a misspelt key is a setting that silently does
// not apply, and an inline secret must be refused rather than ignored.
func Parse(b []byte) (*File, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("fleet: %w", err)
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// safeName is what a server name may contain: it becomes a directory.
var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Validate reports every way the fleet cannot be run as written.
func (f *File) Validate() error {
	var problems []string
	if f.Version != Version {
		problems = append(problems, fmt.Sprintf("version is %d; this passmcp reads version %d", f.Version, Version))
	}
	if len(f.Servers) == 0 {
		problems = append(problems, "no servers")
	}
	if f.Pacing.CallTimeout != "" {
		if _, err := time.ParseDuration(f.Pacing.CallTimeout); err != nil {
			problems = append(problems, "pacing.call_timeout: "+err.Error())
		}
	}
	seen := map[string]bool{}
	for i, s := range f.Servers {
		problems = append(problems, s.problems(i, seen)...)
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return errors.New("fleet:\n  - " + strings.Join(problems, "\n  - "))
}

// problems lists what is wrong with one server entry.
func (s Server) problems(i int, seen map[string]bool) []string {
	var out []string
	where := fmt.Sprintf("servers[%d]", i)
	switch {
	case !safeName.MatchString(s.Name):
		out = append(out, where+": name must be letters, digits, '.', '_' or '-', up to 64 characters")
	case seen[s.Name]:
		out = append(out, where+": name "+s.Name+" is used twice")
	default:
		seen[s.Name] = true
	}
	hasURL, hasCmd := strings.TrimSpace(s.Endpoint) != "", len(s.Command) > 0
	switch {
	case hasURL == hasCmd:
		out = append(out, where+": set exactly one of endpoint and command")
	case s.Transport != "" && s.Transport != s.transport():
		out = append(out, fmt.Sprintf("%s: transport is %q but the entry is a %s server", where, s.Transport, s.transport()))
	}
	return append(out, s.Credential.problems(where)...)
}

// transport is what the entry is, from which target field it sets.
func (s Server) transport() string {
	if len(s.Command) > 0 {
		return "stdio"
	}
	return "http"
}

// problems lists what is wrong with a credential reference.
func (c *Credential) problems(where string) []string {
	if c == nil {
		return nil
	}
	switch c.mode() {
	case "none":
		return nil
	case "bearer":
		if c.TokenEnv == "" {
			return []string{where + ": credential mode bearer needs token_env, the name of the variable holding the token"}
		}
	case "client-credentials":
		if c.ClientID == "" || c.ClientSecretEnv == "" {
			return []string{where + ": credential mode client-credentials needs client_id and client_secret_env"}
		}
	default:
		return []string{fmt.Sprintf("%s: credential mode %q is not bearer, client-credentials or none", where, c.Mode)}
	}
	return nil
}

// mode is the credential mode with its default applied.
func (c *Credential) mode() string {
	if c.Mode != "" {
		return c.Mode
	}
	if c.TokenEnv != "" {
		return "bearer"
	}
	return "none"
}
