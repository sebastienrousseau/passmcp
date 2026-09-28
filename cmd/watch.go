// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"satellion.com/passmcp/internal/baseline"
	"satellion.com/passmcp/internal/diag"
	"satellion.com/passmcp/internal/engine"
	"satellion.com/passmcp/internal/watch"
)

var (
	watchInterval time.Duration
	watchOnce     bool
)

var watchCmd = &cobra.Command{
	Use:   "watch <endpoint>",
	Short: "Report when a server stops being the one you approved.",
	Long: `Watch a server's catalogue and report what changed.

A check tells you a server was sound when you ran it. That is a statement
about a moment, and the threat it cannot see by construction is the one
that waits: the server that passes review and edits its tool descriptions
the following week is the server that gets through.

  passmcp check URL --baseline .passmcp/baseline.json --approve
  passmcp watch URL --baseline .passmcp/baseline.json

A pulse is deliberately small -- connect, list the catalogue, hash it,
compare -- because a watcher that re-ran nine phases on a loop would be the
abusive client passmcp warns everyone else about. Two requests and a string
comparison, every few minutes, and a timer in between.

  --once takes a single pulse and exits, which is the shape a CI job
  wants: exit 2 when the catalogue is not the approved one, 0 when it is,
  and 1 when passmcp never got an answer at all.

Severity is by kind rather than by count. A readOnlyHint becoming true
after approval is critical, because it is the flip that makes a cautious
client start invoking a tool it previously refused. A new optional
property is noise, and is reported as such.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target, err := resolveTarget(cmd, args)
		if err != nil {
			return err
		}
		spec, err := buildSpec(target, nil)
		if err != nil {
			return err
		}
		if strings.TrimSpace(baselineFile) == "" {
			return errors.New("watch needs --baseline: there is nothing to compare against. " +
				"Run `passmcp check <target> --baseline <file> --approve` first")
		}
		approved, err := baseline.Load(baselineFile)
		if err != nil {
			return err
		}

		// Ctrl-C stops the watcher rather than killing it: a long-lived
		// process should say how far it got.
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		ndjson := spec.Output.Format == engine.FormatNDJSON
		enc := json.NewEncoder(os.Stdout)

		res, err := watch.Run(ctx, watch.Options{
			Spec:     spec,
			Approved: approved,
			Interval: watchInterval,
			Once:     watchOnce,
			Version:  Version,
			Sink: func(ev watch.Event) {
				if ndjson {
					_ = enc.Encode(ev)
					return
				}
				writeWatchEvent(ev)
			},
		})
		if err != nil {
			return err
		}

		if approveBaseline && res.Latest != nil {
			if err := baseline.Save(baselineFile, *res.Latest); err != nil {
				return err
			}
			diag.Infof("approved %d tool(s) as the new baseline in %s",
				len(res.Latest.Tools), baselineFile)
		}

		// The exit code is the gate. A watcher that saw a change and
		// returned zero would be a gate that never fails.
		if res.Drifted && !approveBaseline {
			osExit(2)
		}
		return nil
	},
}

// writeWatchEvent prints one event for a person.
//
// On stdout, because with --output text the events are the output. The
// NDJSON form goes to stdout for the same reason, and neither is mixed
// with a diagnostic.
func writeWatchEvent(ev watch.Event) {
	stamp := ev.At.Format("15:04:05")
	switch ev.Kind {
	case "drift":
		fmt.Printf("%s  drift  %s — %s\n", stamp, ev.Target, ev.Detail)
		shown := min(len(ev.Changes), 5)
		for i := range shown {
			c := ev.Changes[i]
			fmt.Printf("           [%s] %s: %s\n", c.Severity, c.Tool, c.Detail)
			if c.Was != "" || c.Now != "" {
				fmt.Printf("               was %q\n               now %q\n", c.Was, c.Now)
			}
		}
		if len(ev.Changes) > shown {
			fmt.Printf("           and %d more\n", len(ev.Changes)-shown)
		}
	case "error":
		fmt.Printf("%s  error  %s — %s\n", stamp, ev.Target, ev.Detail)
	case "settled":
		fmt.Printf("%s  stop   %s\n", stamp, ev.Detail)
	default:
		fmt.Printf("%s  ok     %s — %s\n", stamp, ev.Target, ev.Detail)
	}
}

func init() {
	// The same flag sets check uses. A watch is a loop around the same
	// target, the same credentials and the same policy, so it has to be
	// described the same way -- a second vocabulary for the same facts is
	// how two surfaces start disagreeing about what they were pointed at.
	watchCmd.Flags().AddFlagSet(targetFlags())
	watchCmd.Flags().AddFlagSet(credFlags())
	watchCmd.Flags().AddFlagSet(policyFlags())
	watchCmd.Flags().AddFlagSet(paceFlags())
	watchCmd.Flags().AddFlagSet(outputFlags())

	watchCmd.Flags().DurationVar(&watchInterval, "interval", watch.DefaultInterval,
		"how long to wait between pulses")
	watchCmd.Flags().BoolVar(&watchOnce, "once", false,
		"take a single pulse and exit; exit 2 when the catalogue is not the approved one")
}
