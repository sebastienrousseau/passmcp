// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/telemetry"
)

// read and prompt are call's siblings for the two other things a server
// offers. Both are non-mutating by the MCP specification, which is why no
// policy flag gates them (ADR-0004): a server that writes on
// resources/read is misbehaving in a way no client-side policy could
// detect, exactly as one that lies in readOnlyHint is.

var promptArgs []string

var readCmd = &cobra.Command{
	Use:   "read <endpoint> <uri>",
	Short: "Connect and read one resource (resources/read).",
	Long: `Read a single resource by URI and print its contents with timing.

  passmcp read https://mcp.example.com/mcp file:///README.md
  passmcp read https://mcp.example.com/mcp ui://dashboard --output json

Text contents are printed as they are; binary (blob) contents are
described by URI, size and MIME type rather than written to a terminal.
resources/read is non-mutating by the MCP specification, so no policy flag
is needed.

With --stdio the server is a program, given after --, and the one
positional argument left is the URI:

  passmcp read --stdio <uri> -- <command> [args...]`,
	// Not ExactArgs(2), for the same reason as call: with --stdio the
	// endpoint is replaced by a command after --.
	Args: cobra.ArbitraryArgs,
	RunE: runRead,
}

var promptCmd = &cobra.Command{
	Use:   "prompt <endpoint> <name>",
	Short: "Connect and render one prompt (prompts/get).",
	Long: `Render a single prompt with the given arguments and print its messages
with timing. Arguments come from --arg name=value (repeatable); prompt
arguments are strings, so the value is taken as written.

  passmcp prompt https://mcp.example.com/mcp summarise --arg doc=README.md
  passmcp prompt https://mcp.example.com/mcp triage --output json

prompts/get is non-mutating by the MCP specification, so no policy flag is
needed.

With --stdio the server is a program, given after --, and the one
positional argument left is the prompt name:

  passmcp prompt --stdio <name> --arg key=value -- <command> [args...]`,
	Args: cobra.ArbitraryArgs,
	RunE: runPrompt,
}

// operandSession is a connected client for one read or prompt.
type operandSession struct {
	client  *passmcp.Client
	rec     *telemetry.Recorder
	operand string
}

// openOperand validates the output format, resolves the target and the
// named operand, and connects with the operator's credentials.
func openOperand(cmd *cobra.Command, args []string, verb, noun string) (*operandSession, error) {
	if output != "text" && output != "json" {
		return nil, fmt.Errorf("--output %q: %s writes text or json", output, verb)
	}
	target, operand, err := operandTarget(cmd, args, verb, noun)
	if err != nil {
		return nil, err
	}
	cr, err := buildCreds()
	if err != nil {
		return nil, err
	}
	client, rec, err := connectWithCreds(cmd, target, cr)
	if err != nil {
		return nil, err
	}
	return &operandSession{client: client, rec: rec, operand: operand}, nil
}

// fail is err with every secret the recorder knows masked. The server
// chooses an error's text, and a server that echoes a request's
// credentials back must not have them printed.
func (s *operandSession) fail(err error) error {
	return errors.New(s.rec.Redactor.String(err.Error()))
}

func runRead(cmd *cobra.Command, args []string) error {
	s, err := openOperand(cmd, args, "read", "uri")
	if err != nil {
		return err
	}
	// Over stdio this owns a process, closed on every path out.
	defer func() { _ = s.client.Close() }()
	t0 := time.Now()
	res, err := s.client.ReadResource(telemetry.WithPhase(cmdContext(cmd), "read", s.operand), s.operand)
	d := time.Since(t0)
	if err != nil {
		return s.fail(err)
	}
	if output == "json" {
		return writeIndentedJSON(os.Stdout, map[string]any{"uri": s.operand, "duration_ms": float64(d) / 1e6, "result": res, "telemetry": s.rec.Summary()})
	}
	writeResource(os.Stdout, s.operand, d, res)
	return nil
}

func runPrompt(cmd *cobra.Command, args []string) error {
	argsMap, err := parsePromptArgs(promptArgs)
	if err != nil {
		return err
	}
	s, err := openOperand(cmd, args, "prompt", "name")
	if err != nil {
		return err
	}
	defer func() { _ = s.client.Close() }()
	t0 := time.Now()
	res, err := s.client.GetPrompt(telemetry.WithPhase(cmdContext(cmd), "prompt", s.operand), s.operand, argsMap)
	d := time.Since(t0)
	if err != nil {
		return s.fail(err)
	}
	if output == "json" {
		return writeIndentedJSON(os.Stdout, map[string]any{"prompt": s.operand, "arguments": argsMap, "duration_ms": float64(d) / 1e6, "result": res, "telemetry": s.rec.Summary()})
	}
	writePrompt(os.Stdout, s.operand, d, res)
	return nil
}

// parsePromptArgs reads --arg name=value pairs. Prompt arguments are
// strings in the specification, so a value is never parsed as JSON.
func parsePromptArgs(items []string) (map[string]string, error) {
	out := map[string]string{}
	for _, a := range items {
		k, v, ok := strings.Cut(a, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("--arg %q must be name=value", a)
		}
		out[k] = v
	}
	return out, nil
}

// writeIndentedJSON writes v as indented JSON.
func writeIndentedJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// writeResource prints a resource for a person.
func writeResource(w io.Writer, uri string, d time.Duration, res *passmcp.ReadResourceResult) {
	_, _ = fmt.Fprintf(w, "%s ok in %s\n", uri, d.Round(time.Millisecond))
	for _, c := range res.Contents {
		if c.Blob != "" {
			_, _ = fmt.Fprintf(w, "[blob %s, %d bytes, %s]\n", c.URI, blobSize(c.Blob), c.MimeType)
			continue
		}
		_, _ = fmt.Fprintln(w, c.Text)
	}
}

// writePrompt prints a rendered prompt for a person.
func writePrompt(w io.Writer, name string, d time.Duration, res *passmcp.GetPromptResult) {
	_, _ = fmt.Fprintf(w, "%s ok in %s\n", name, d.Round(time.Millisecond))
	if res.Description != "" {
		_, _ = fmt.Fprintln(w, res.Description)
	}
	for _, m := range res.Messages {
		_, _ = fmt.Fprintf(w, "[%s] %s\n", m.Role, contentLine(m.Content))
	}
}

// contentLine is a content block as one line: text as written, anything
// else described.
func contentLine(c passmcp.Content) string {
	if c.Type == "text" {
		return c.Text
	}
	return fmt.Sprintf("[%s content, %d bytes, %s]", c.Type, len(c.Data), c.MimeType)
}

// blobSize is the decoded size of a base64 blob, or its encoded length
// when it does not decode.
func blobSize(b64 string) int {
	if raw, err := base64.StdEncoding.DecodeString(b64); err == nil {
		return len(raw)
	}
	return len(b64)
}

func init() {
	for _, c := range []*cobra.Command{readCmd, promptCmd} {
		c.Flags().AddFlagSet(targetFlags())
		c.Flags().AddFlagSet(credFlags())
		c.Flags().StringVar(&output, "output", "text", "output format: text or json")
	}
	promptCmd.Flags().StringArrayVar(&promptArgs, "arg", nil, "prompt argument name=value (repeatable)")
}
