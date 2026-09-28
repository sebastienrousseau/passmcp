// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package config reads passmcp's configuration file. Keys are flag names, so
// the file needs no schema of its own and covers every flag automatically.
//
// Precedence, highest first: an explicit flag, the selected profile, the
// defaults block, the flag's built-in default. Environment variables are a
// separate layer handled by the creds package for secrets only.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// File is the on-disk shape.
type File struct {
	Defaults map[string]any     `json:"defaults,omitempty"`
	Profiles map[string]Profile `json:"profiles,omitempty"`
}

// Profile names a server and the settings to test it with.
type Profile struct {
	Endpoint string         `json:"endpoint"`
	Settings map[string]any `json:"settings,omitempty"`
}

// Applied records where an effective value came from, for --explain.
type Applied struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

// DefaultPath is $XDG_CONFIG_HOME/passmcp/config.json or ~/.config/passmcp/config.json.
func DefaultPath() string {
	if p := os.Getenv("PASSMCP_CONFIG"); p != "" {
		return p
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "passmcp", "config.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".config", "passmcp", "config.json")
	}
	return filepath.Join(home, ".config", "passmcp", "config.json")
}

// Load reads and validates a config file.
func Load(path string) (File, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the operator names their own config file
	if err != nil {
		return File{}, err
	}
	var f File
	dec := json.NewDecoder(strings.NewReader(stripComments(string(raw))))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return File{}, fmt.Errorf("%s: %w", path, err)
	}
	for name, p := range f.Profiles {
		if p.Endpoint == "" {
			return File{}, fmt.Errorf("%s: profile %q has no endpoint", path, name)
		}
	}
	return f, nil
}

// LoadOptional is Load with a missing default file treated as empty. An
// explicitly named file that is missing is still an error.
func LoadOptional(path string) (File, string, error) {
	explicit := path != ""
	if !explicit {
		path = DefaultPath()
	}
	f, err := Load(path)
	if err != nil {
		if !explicit && errors.Is(err, os.ErrNotExist) {
			return File{}, path, nil
		}
		return File{}, path, err
	}
	return f, path, nil
}

// Apply writes values onto cmd's flags, skipping any the user set
// explicitly. A key that matches no flag on this command but is known to
// the CLI is ignored (one file serves every command); a key unknown
// everywhere is an error, because a silently ignored typo is worse than a
// failure.
func Apply(cmd *cobra.Command, values map[string]any, source string, known map[string]bool) ([]Applied, error) {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var applied []Applied
	for _, key := range keys {
		flag := cmd.Flags().Lookup(key)
		if flag == nil {
			if known[key] {
				continue
			}
			return nil, fmt.Errorf("%s: unknown setting %q (settings are named after flags; see `passmcp check --help`)", source, key)
		}
		if flag.Changed {
			continue
		}
		str, err := toString(values[key])
		if err != nil {
			return nil, fmt.Errorf("%s: setting %q: %w", source, key, err)
		}
		if err := flag.Value.Set(str); err != nil {
			return nil, fmt.Errorf("%s: setting %q = %v: %w", source, key, values[key], err)
		}
		applied = append(applied, Applied{Key: key, Value: str, Source: source})
	}
	return applied, nil
}

func toString(v any) (string, error) {
	switch t := v.(type) {
	case string:
		return t, nil
	case bool:
		return strconv.FormatBool(t), nil
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10), nil
		}
		return strconv.FormatFloat(t, 'f', -1, 64), nil
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			s, err := toString(e)
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return strings.Join(parts, ","), nil
	case nil:
		return "", errors.New("value is null")
	}
	return "", fmt.Errorf("unsupported value type %T", v)
}

// Template renders a commented starter file listing every flag of cmd,
// each on a line that is valid JSON once uncommented.
func Template(cmd *cobra.Command) string {
	var b strings.Builder
	b.WriteString("{\n  \"defaults\": {\n")
	var lines []string
	cmd.Flags().VisitAll(func(f *pflagFlag) {
		if f.Name == "help" || f.Name == "config" || f.Name == "profile" {
			return
		}
		lines = append(lines, fmt.Sprintf("    // %s\n    // \"%s\": %s", f.Usage, f.Name, jsonDefault(f)))
	})
	b.WriteString(strings.Join(lines, ",\n"))
	b.WriteString("\n  },\n  \"profiles\": {\n    // \"prod\": {\n    //   \"endpoint\": \"https://mcp.example.com/mcp\",\n    //   \"settings\": { \"auth\": \"client-credentials\", \"client-id\": \"acme\", \"client-secret-env\": \"ACME_SECRET\" }\n    // }\n  }\n}\n")
	return b.String()
}

func jsonDefault(f *pflagFlag) string {
	switch f.Value.Type() {
	case "bool", "int", "int64", "uint64", "float64":
		return f.DefValue
	case "stringArray", "stringSlice":
		return "[]"
	case "duration":
		return strconv.Quote(f.DefValue)
	}
	return strconv.Quote(f.DefValue)
}

// stripComments drops lines that are only a // comment, so the template
// written by `passmcp config init` loads as-is.
func stripComments(s string) string {
	lines := strings.Split(s, "\n")
	out := lines[:0]
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "//") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}
