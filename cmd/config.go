// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"satellion.com/passmcp/internal/config"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Create, validate or show the configuration file.",
	Long: `The config file holds defaults keyed by flag name and named profiles:

  {
    "defaults": { "rps": 4, "report-dir": "./passmcp-reports" },
    "profiles": {
      "prod": {
        "endpoint": "https://mcp.example.com/mcp",
        "settings": { "auth": "client-credentials", "client-id": "acme",
                      "client-secret-env": "ACME_SECRET", "param": ["profile_id=t1"] }
      }
    }
  }

Secrets belong in the environment, referenced with *-env settings.
Precedence: explicit flag > profile > defaults > built-in default.`,
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Write a commented starter config listing every setting.",
	RunE: func(cmd *cobra.Command, args []string) error {
		path := configPath
		if path == "" {
			path = config.DefaultPath()
		}
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists; remove it first", path)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(config.Template(checkCmd)), 0o600); err != nil {
			return err
		}
		fmt.Println("wrote", path)
		return nil
	},
}

var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Parse the config file and report problems.",
	RunE: func(cmd *cobra.Command, args []string) error {
		f, path, err := config.LoadOptional(configPath)
		if err != nil {
			return err
		}
		known := knownFlagNames()
		for k := range f.Defaults {
			if !known[k] {
				return fmt.Errorf("%s: defaults: unknown setting %q", path, k)
			}
		}
		for name, p := range f.Profiles {
			for k := range p.Settings {
				if !known[k] {
					return fmt.Errorf("%s: profile %s: unknown setting %q", path, name, k)
				}
			}
		}
		fmt.Printf("%s: ok (%d defaults, %d profiles)\n", path, len(f.Defaults), len(f.Profiles))
		return nil
	},
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Print the effective config file as JSON.",
	RunE: func(cmd *cobra.Command, args []string) error {
		f, _, err := config.LoadOptional(configPath)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(f)
	},
}

func init() {
	configCmd.AddCommand(configInitCmd, configValidateCmd, configShowCmd)
}
