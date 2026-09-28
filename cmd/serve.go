// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/spf13/cobra"
	"satellion.com/passmcp/internal/diag"
	"satellion.com/passmcp/internal/web"
)

var (
	serveAddr        string
	serveAllowRemote bool
	serveNoOpen      bool
	servePublic      bool
	serveAllowFile   string
	serveRate        int
	serveBurst       int
	serveTrustProxy  bool
	serveAllowStdio  bool
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run passmcp's web interface on this machine.",
	Long: `Start passmcp's web interface: the same diagnostic as ` + "`passmcp check`" + `, driven
from a browser.

The run happens here. The endpoint you test, the credentials it uses and
the report it produces never leave this machine, which is the difference
between this and a hosted tester: one of those asks you to hand a working
credential to somebody else's server.

The listener binds loopback, validates Origin, and requires the token in
the URL it prints. Those are the same rules passmcp tells every MCP server
to follow.

Examples:
  passmcp serve
  passmcp serve --addr 127.0.0.1:8080
  passmcp serve --no-open`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		var allowed *web.Allowlist
		if servePublic {
			if serveAllowFile == "" {
				return fmt.Errorf("--public needs --allow-file naming the servers this deployment may scan.\n" +
					"  Without one it would send requests wherever it was asked to, which is the\n" +
					"  thing passmcp reports other servers for")
			}
			// The overrides that make local debugging pleasant are the ones
			// that make a public deployment dangerous, so they are refused
			// here rather than ignored: a flag that appears to work and does
			// nothing is worse than one that fails.
			for _, f := range []string{"insecure-allow-private-hosts", "insecure-allow-http-auth", "allow-resource-mismatch"} {
				if cmd.Flags().Changed(f) || cmd.Root().PersistentFlags().Changed(f) {
					return fmt.Errorf("--%s cannot be combined with --public", f)
				}
			}
			var err error
			if allowed, err = web.LoadAllowlist(serveAllowFile); err != nil {
				return err
			}
			// A public deployment is reached from somewhere else by
			// definition, so a loopback bind would serve nobody.
			serveAllowRemote = true
		}

		srv, err := web.New(web.Options{
			Addr:             serveAddr,
			AllowRemote:      serveAllowRemote,
			Version:          Version,
			Public:           servePublic,
			Allowed:          allowed,
			RatePerMinute:    serveRate,
			RateBurst:        serveBurst,
			TrustProxyHeader: serveTrustProxy,
			AllowStdio:       serveAllowStdio,
			Open: func(url string) {
				if servePublic {
					fmt.Fprintf(os.Stderr, "\n  passmcp is serving a public diagnostic at\n\n    %s\n\n", url)
					fmt.Fprintf(os.Stderr, "  No credentials are accepted. %d server(s) may be scanned:\n", len(allowed.Endpoints()))
					for _, e := range allowed.Endpoints() {
						fmt.Fprintf(os.Stderr, "    %s\n", e)
					}
					fmt.Fprintf(os.Stderr, "\n  Press Ctrl-C to stop.\n\n")
					return
				}
				fmt.Fprintf(os.Stderr, "\n  passmcp is running at\n\n    %s\n\n", url)
				fmt.Fprintf(os.Stderr, "  The token in that URL is what authorises the page. Anyone with it\n")
				fmt.Fprintf(os.Stderr, "  can start runs from this machine, so treat it like a password.\n")
				fmt.Fprintf(os.Stderr, "  Press Ctrl-C to stop.\n\n")
				if !serveNoOpen {
					openBrowser(cmd.Context(), url)
				}
			},
		})
		if err != nil {
			return err
		}
		return srv.Serve(cmd.Context())
	},
}

func init() {
	serveCmd.Flags().StringVar(&serveAddr, "addr", "127.0.0.1:0", "listen address; a port of 0 picks a free one")
	serveCmd.Flags().BoolVar(&serveAllowRemote, "allow-remote", false, "allow a non-loopback bind (this listener can start authenticated runs)")
	serveCmd.Flags().BoolVar(&serveNoOpen, "no-open", false, "do not open a browser")
	serveCmd.Flags().BoolVar(&servePublic, "public", false, "serve a credential-free diagnostic to anyone who can reach it (requires --allow-file)")
	serveCmd.Flags().StringVar(&serveAllowFile, "allow-file", "", "JSON file naming the servers a --public deployment may scan")
	serveCmd.Flags().IntVar(&serveRate, "rate", 6, "runs per minute per caller in --public mode")
	serveCmd.Flags().IntVar(&serveBurst, "burst", 3, "runs a caller may start at once in --public mode")
	serveCmd.Flags().BoolVar(&serveTrustProxy, "trust-proxy-header", false, "honour X-Forwarded-For for rate limiting (only behind a proxy you control)")
	serveCmd.Flags().BoolVar(&serveAllowStdio, "allow-stdio", false, "let a run in the browser start a program on this machine instead of fetching a URL (off by default: that is a shell, not a diagnostic)")
}

// openBrowser is best-effort: failing to open one is not a reason to fail
// the command, because the URL is already on screen.
func openBrowser(ctx context.Context, url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	default:
		cmd = "xdg-open"
	}
	path, err := exec.LookPath(cmd)
	if err != nil {
		return
	}
	// #nosec G204 -- cmd is one of three literals above; url is passmcp's own
	// loopback address with a token it just minted.
	if err := exec.CommandContext(ctx, path, append(args, url)...).Start(); err != nil {
		diag.Debugf("could not open a browser: %v", err)
	}
}
