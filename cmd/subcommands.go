// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"satellion.com/passmcp"
	"satellion.com/passmcp/auth"
	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/diag"
	"satellion.com/passmcp/internal/engine"
	"satellion.com/passmcp/internal/telemetry"
	"satellion.com/passmcp/internal/tui"
	"satellion.com/passmcp/transport"
)

var connectCmd = &cobra.Command{
	Use:   "connect <endpoint>",
	Short: "Run only the connection phases: net, discovery, auth, handshake.",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCheck(cmd, args, []string{"net", "discovery", "auth", "handshake"})
	},
}

var toolsCmd = &cobra.Command{
	Use:   "tools <endpoint>",
	Short: "Connect and audit the catalog without invoking anything.",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCheck(cmd, args, []string{"net", "discovery", "auth", "handshake", "catalog"})
	},
}

var (
	callArgsJSON string
	callArgs     []string
)

var callCmd = &cobra.Command{
	Use:   "call <endpoint> <tool>",
	Short: "Connect and invoke one tool with the given arguments.",
	Long: `Invoke a single tool and print its result with timing. Arguments come
from --arg field=value (repeatable, JSON parsed when possible) or --json.

  passmcp call https://mcp.example.com/mcp search --arg q=invoices --arg limit=5
  passmcp call https://mcp.example.com/mcp get_time --json '{}' --output json

With --stdio the server is a program, given after --, and the one positional
argument left is the tool to call:

  passmcp call --stdio get-sum --arg a=2 --arg b=3 -- npx -y @modelcontextprotocol/server-everything stdio`,
	// Not ExactArgs(2): with --stdio the endpoint is replaced by a command
	// after --, so what is left before it is the tool name alone.
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		target, tool, err := callTarget(cmd, args)
		if err != nil {
			return err
		}
		cr, err := buildCreds()
		if err != nil {
			return err
		}
		argsMap := map[string]any{}
		if callArgsJSON != "" {
			if err := json.Unmarshal([]byte(callArgsJSON), &argsMap); err != nil {
				return fmt.Errorf("--json: %w", err)
			}
		}
		for _, a := range callArgs {
			k, v, ok := strings.Cut(a, "=")
			if !ok {
				return fmt.Errorf("--arg %q must be field=value", a)
			}
			argsMap[k] = jsonOrString(v)
		}
		client, rec, err := connectWithCreds(cmd, target, cr)
		if err != nil {
			return err
		}
		// Over stdio this owns a process. It is closed on every path out,
		// including the error paths below, which is why the defer is here
		// rather than after the call.
		defer func() { _ = client.Close() }()
		t0 := time.Now()
		res, err := client.CallTool(telemetry.WithPhase(cmdContext(cmd), "call", tool), tool, argsMap)
		d := time.Since(t0)
		if err != nil {
			return err
		}
		if output == "json" {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]any{"tool": tool, "arguments": argsMap, "duration_ms": float64(d) / 1e6, "result": res, "telemetry": rec.Summary()})
		}
		status := "ok"
		if res.IsError {
			status = "isError"
		}
		fmt.Printf("%s %s in %s\n", tool, status, d.Round(time.Millisecond))
		for _, c := range res.Content {
			switch c.Type {
			case "text":
				fmt.Println(c.Text)
			default:
				fmt.Printf("[%s content, %d bytes, %s]\n", c.Type, len(c.Data), c.MimeType)
			}
		}
		if len(res.StructuredContent) > 0 {
			fmt.Printf("structuredContent: %s\n", res.StructuredContent)
		}
		return nil
	},
}

var loginCmd = &cobra.Command{
	Use:   "login <endpoint>",
	Short: "Authorize as a user (PKCE) and store the token for later runs.",
	Long: `Run the OAuth 2.1 authorization-code flow with PKCE against the server's
authorization server, open the consent URL in your browser, receive the
redirect on a loopback port, and save the tokens (0600) to the store so
` + "`passmcp check --auth authorization-code`" + ` can use them.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		endpoint, err := resolveEndpoint(args)
		if err != nil {
			return err
		}
		authMode = string(creds.ModeAuthorizationCode)
		cr, err := buildCreds()
		if err != nil {
			return err
		}
		rec := telemetry.New()
		for _, s := range cr.Secrets() {
			rec.Redactor.Add(s)
		}
		cfg := passmcp.Config{Endpoint: endpoint, HTTPClient: &http.Client{Timeout: 60 * time.Second, Transport: rec.Wrap(auth.URLPolicy{}.EndpointTransport(endpoint))}, ClientInfo: passmcp.Implementation{Name: "passmcp", Version: Version}}
		cr.Apply(&cfg)
		client, err := passmcp.New(cfg)
		if err != nil {
			return err
		}
		res, err := client.Connect(cmdContext(cmd))
		if err != nil {
			return err
		}
		if res.Status == passmcp.StatusConnected {
			fmt.Fprintln(os.Stderr, "server did not require authorization; nothing to store")
			return nil
		}
		port := redirectPort
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return fmt.Errorf("listen on redirect port %d: %w", port, err)
		}
		type cb struct{ code, state, iss, errText string }
		ch := make(chan cb, 1)
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			// iss (RFC 9207) names the authorization server that answered;
			// CompleteAuthorizationFrom refuses one that is not the issuer the
			// code was requested from, which is what stops a mix-up attack.
			result := cb{code: q.Get("code"), state: q.Get("state"), iss: q.Get("iss")}
			msg := "Authorization complete. You can close this window."
			if e := q.Get("error"); e != "" {
				result = cb{errText: e + ": " + q.Get("error_description")}
				msg = "Authorization failed. You can close this window."
			}
			// Flush the page to the browser before waking the command, which
			// will shut the server down as soon as it has the code.
			_, _ = fmt.Fprintln(w, msg)
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
			ch <- result
		}),
			// This listens on the operator's machine for as long as the
			// browser flow takes. Without header and read timeouts a single
			// stalled connection holds it open indefinitely.
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       30 * time.Second,
		}
		go func() { _ = srv.Serve(ln) }()
		defer func() {
			sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(sctx) // graceful: lets the callback handler finish its response
		}()
		fmt.Fprintf(os.Stderr, "\nOpen this URL to authorize:\n\n  %s\n\nwaiting for the redirect on %s ...\n", res.AuthorizationURL, ln.Addr())
		var r cb
		select {
		case <-cmdContext(cmd).Done():
			return cmdContext(cmd).Err()
		case r = <-ch:
		}
		if r.errText != "" {
			return errors.New("authorization server returned " + r.errText)
		}
		done, err := client.CompleteAuthorizationFrom(cmdContext(cmd), r.code, r.state, r.iss)
		if err != nil {
			return err
		}
		cur := currentToken(client)
		if cur == nil {
			return errors.New("no token after authorization")
		}
		st := creds.StoredToken{Endpoint: endpoint, AccessToken: cur.AccessToken, RefreshToken: cur.RefreshToken, TokenType: cur.TokenType, Scope: cur.Scope, Expiry: cur.Expiry}
		if d := done.Discovery; d != nil {
			st.TokenURL, st.Resource = d.Server.TokenEndpoint, d.Resource
			st.Issuer = d.Server.Issuer
			if d.Registration != nil {
				st.ClientID, st.ClientSecret = d.Registration.ClientID, d.Registration.ClientSecret
			}
		}
		store := &creds.Store{}
		if err := store.Put(st); err != nil {
			return err
		}
		// Say where the secret actually went: "stored in tokens.json" would
		// be wrong when the OS keychain holds it, and an operator auditing
		// their machine needs to know which.
		switch backend := store.Backend(); backend {
		case "file":
			fmt.Fprintf(os.Stderr, "authorized as a user of %s; token stored in %s (mode 0600)\n", done.Initialize.ServerInfo.Name, creds.DefaultStorePath())
			fmt.Fprintf(os.Stderr, "note: no OS keyring was available, so the refresh token is on disk in the clear\n")
		default:
			fmt.Fprintf(os.Stderr, "authorized as a user of %s; secrets stored in the %s keyring, the rest in %s\n", done.Initialize.ServerInfo.Name, backend, creds.DefaultStorePath())
		}
		diag.Infof("run: passmcp check %s --auth authorization-code", endpoint)
		return nil
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the passmcp version.",
	Run: func(cmd *cobra.Command, args []string) {
		if stdoutIsTTY() && tui.ShowLogo() {
			fmt.Print(tui.GetStyledLogo())
		}
		fmt.Println("passmcp", Version)
	},
}

func init() {
	for _, c := range []*cobra.Command{connectCmd, toolsCmd} {
		c.Flags().AddFlagSet(targetFlags())
		c.Flags().AddFlagSet(credFlags())
		c.Flags().AddFlagSet(outputFlags())
		c.Flags().AddFlagSet(paceFlags())
	}
	callCmd.Flags().AddFlagSet(targetFlags())
	callCmd.Flags().AddFlagSet(credFlags())
	callCmd.Flags().StringVar(&output, "output", "text", "output format: text or json")
	callCmd.Flags().StringVar(&callArgsJSON, "json", "", "arguments as a JSON object")
	callCmd.Flags().StringArrayVar(&callArgs, "arg", nil, "argument field=value (repeatable)")
	loginCmd.Flags().AddFlagSet(credFlags())
}

// connectWithCreds builds a recorded client and connects, resuming a stored
// user token when the mode is authorization-code.
func connectWithCreds(cmd *cobra.Command, target engine.TargetSpec, cr *creds.Credentials) (*passmcp.Client, *telemetry.Recorder, error) {
	rec := telemetry.New()
	for _, s := range cr.Secrets() {
		rec.Redactor.Add(s)
	}
	endpoint := target.Endpoint
	if target.Stdio() {
		client, err := passmcp.NewStdio(cmdContext(cmd), passmcp.Config{
			Stdio: &passmcp.StdioConfig{
				Command: target.Command, Args: target.Args,
				Dir: target.Dir, PassEnv: target.PassEnv, Env: target.Env,
				Observe: func(ctx context.Context, m transport.StdioMessage) {
					rec.RecordPipe(ctx, target.Describe(), m.Sent, m.Received, m.Duration, m.Err)
				},
			},
			ClientInfo: passmcp.Implementation{Name: "passmcp", Version: Version},
		})
		if err != nil {
			return nil, nil, err
		}
		if _, err := client.Connect(cmdContext(cmd)); err != nil {
			_ = client.Close()
			return nil, nil, err
		}
		return client, rec, nil
	}
	cfg := passmcp.Config{Endpoint: endpoint, HTTPClient: &http.Client{Timeout: 60 * time.Second, Transport: rec.Wrap(auth.URLPolicy{}.EndpointTransport(endpoint))}, ClientInfo: passmcp.Implementation{Name: "passmcp", Version: Version}}
	cr.Apply(&cfg)
	client, err := passmcp.New(cfg)
	if err != nil {
		return nil, nil, err
	}
	if cr.Effective() == creds.ModeAuthorizationCode {
		st, err := (&creds.Store{}).Get(endpoint)
		if err != nil {
			return nil, nil, err
		}
		if st == nil {
			return nil, nil, fmt.Errorf("no stored token for %s; run `passmcp login %s`", endpoint, endpoint)
		}
		if _, err := client.Resume(cmdContext(cmd), st.Source(creds.HTTP{C: client.HTTPClient()})); err != nil {
			return nil, nil, err
		}
		return client, rec, nil
	}
	res, err := client.Connect(cmdContext(cmd))
	if err != nil {
		return nil, nil, err
	}
	if res.Status != passmcp.StatusConnected {
		return nil, nil, errors.New("server requires a user login; run `passmcp login` first")
	}
	return client, rec, nil
}
