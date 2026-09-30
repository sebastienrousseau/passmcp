// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package cmd provides passmcp's command-line interface.
package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"satellion.com/passmcp/internal/config"
	"satellion.com/passmcp/internal/diag"
)

// Version is injected at release time via
// -ldflags "-X satellion.com/passmcp/cmd.Version=<version>".
var Version = "dev"

var (
	configPath  string
	profileName string
	logLevel    string
	logFormat   string
	osExit      = os.Exit
)

var rootCmd = &cobra.Command{
	Use:   "passmcp",
	Short: "Onboard, test and diagnose remote MCP servers end to end.",
	Long: `passmcp connects to a Model Context Protocol server the way an agent
would, walks nine phases from DNS to token recovery, and writes a report in
which every finding cites the request that proved it. Secrets never reach
the report.

Credentials come from flags, PASSMCP_* environment variables, or a profile
in the config file. Results go to stdout in the format --output selects;
diagnostics go to stderr under --log-level.`,
	SilenceErrors: true,
	SilenceUsage:  true,
}

// applyConfig layers the config file's defaults and the selected profile
// onto the command's flags, without overriding anything set explicitly.
func applyConfig(cmd *cobra.Command) error {
	f, path, err := config.LoadOptional(configPath)
	if err != nil {
		return err
	}
	known := knownFlagNames()
	if _, err := config.Apply(cmd, f.Defaults, "config defaults ("+path+")", known); err != nil {
		return err
	}
	if profileName != "" {
		p, ok := f.Profiles[profileName]
		if !ok {
			return fmt.Errorf("profile %q not found in %s", profileName, path)
		}
		if _, err := config.Apply(cmd, p.Settings, "profile "+profileName, known); err != nil {
			return err
		}
		if endpointFromProfile == "" {
			endpointFromProfile = p.Endpoint
		}
	}
	return nil
}

// endpointFromProfile is set by applyConfig when --profile names a server.
var endpointFromProfile string

// resolveEndpoint takes the positional endpoint or the profile's.
func resolveEndpoint(args []string) (string, error) {
	if len(args) > 0 && args[0] != "" {
		return args[0], nil
	}
	if endpointFromProfile != "" {
		return endpointFromProfile, nil
	}
	return "", fmt.Errorf("an endpoint URL is required (positional argument, or --profile <name>)")
}

// Execute runs the CLI.
func Execute() { ExecuteContext(context.Background()) }

// ExecuteContext runs the CLI under ctx.
func ExecuteContext(ctx context.Context) {
	rootCmd.SetContext(ctx)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "passmcp: %v\n", err)
		fmt.Fprintf(os.Stderr, "\nRun 'passmcp --help' for usage.\n")
		osExit(1)
	}
}

func init() {
	// Assigned here rather than in the literal: the hook reaches
	// knownFlagNames, which walks rootCmd, and Go rejects that cycle in an
	// initializer.
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if env := os.Getenv(diag.EnvVar); env != "" && !cmd.Flags().Changed("log-level") {
			logLevel = env
		}
		lvl, err := diag.ParseLevel(logLevel)
		if err != nil {
			return err
		}
		diag.SetLevel(lvl)
		fmtv, err := diag.ParseFormat(logFormat)
		if err != nil {
			return err
		}
		diag.SetFormat(fmtv)
		// `config init` exists to create the file; loading it first would
		// reject the very path it is about to write.
		if cmd.Name() == "init" && cmd.Parent() != nil && cmd.Parent().Name() == "config" {
			return nil
		}
		return applyConfig(cmd)
	}
	installStyledHelp(rootCmd)
	pf := rootCmd.PersistentFlags()
	pf.StringVar(&configPath, "config", "", "config file (default "+tildePath(config.DefaultPath())+")")
	pf.StringVar(&profileName, "profile", "", "profile from the config file supplying the endpoint and settings")
	pf.StringVar(&logLevel, "log-level", "info", "diagnostic verbosity on stderr: error, warn, info or debug ("+diag.EnvVar+")")
	pf.StringVar(&logFormat, "log-format", "human", "diagnostic format on stderr: human or json")
	rootCmd.AddCommand(checkCmd, connectCmd, discoverCmd, toolsCmd, callCmd, readCmd, promptCmd, serveCmd, loginCmd, attestCmd, verifyCmd, badgeCmd, sbomCmd, overlapCmd, explainCmd, watchCmd, fleetCmd, evidenceCmd, a2aCmd, configCmd, versionCmd)
}

// Root returns the root command, for documentation generators.
func Root() *cobra.Command { return rootCmd }

// tildePath shortens a path under the home directory to ~/… for display.
func tildePath(p string) string {
	if home, err := os.UserHomeDir(); err == nil && home != "" && strings.HasPrefix(p, home) {
		return "~" + strings.TrimPrefix(p, home)
	}
	return p
}
