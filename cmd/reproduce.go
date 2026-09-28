// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/pflag"
	"satellion.com/passmcp-reporting/attestation"
	"satellion.com/passmcp/internal/attest"
	"satellion.com/passmcp/internal/diag"
	"satellion.com/passmcp/internal/engine"
)

// A statement can come from anyone, so --reproduce takes from it only what
// decides how the server is measured: phases, pacing, which tools and with
// which arguments, egress watching, the baseline. What decides what passmcp
// may touch comes from the operator's command line and nowhere else:
//
//   - the target, which --endpoint must name and the statement must cover;
//   - the credentials, which a statement never carries by value and whose
//     environment-variable names it recorded are not read, since a hostile
//     statement could otherwise choose which of the operator's secrets to
//     send to an endpoint it chose;
//   - the permissions, which must match the plan's exactly, because a
//     comparison between two runs allowed different things measures the
//     permissions rather than the server.

var (
	verifyReproduce bool
	reproPerm       reproducePermissions
	reproSet        *pflag.FlagSet
)

// reproducePermissions are the policy switches a plan records and the
// operator has to grant again. Separate variables from check's, so that a
// flag given to verify cannot leak into anything else.
type reproducePermissions struct {
	AllowMutations, AllowDestructive      bool
	AllowPlaintextAuth, AllowPrivateHosts bool
	AllowResourceMismatch, SkipEraCheck   bool
	// FaultUpstream is here rather than with the measurement choices: it
	// makes the server's world worse on purpose, so a statement cannot
	// switch it on for somebody else.
	FaultUpstream bool
}

func reproduceFlags() *pflag.FlagSet {
	if reproSet != nil {
		return reproSet
	}
	fs := pflag.NewFlagSet("reproduce", pflag.ContinueOnError)
	fs.BoolVar(&verifyReproduce, "reproduce", false, "repeat the run the statement records against --endpoint and gate on what got worse (contacts the target)")
	fs.BoolVar(&reproPerm.AllowMutations, "allow-mutations", false, "with --reproduce: grant what the recorded run was granted")
	fs.BoolVar(&reproPerm.AllowDestructive, "allow-destructive", false, "with --reproduce: grant what the recorded run was granted")
	fs.BoolVar(&reproPerm.AllowPrivateHosts, "insecure-allow-private-hosts", false, "with --reproduce: grant what the recorded run was granted")
	fs.BoolVar(&reproPerm.AllowPlaintextAuth, "insecure-allow-http-auth", false, "with --reproduce: grant what the recorded run was granted")
	fs.BoolVar(&reproPerm.AllowResourceMismatch, "allow-resource-mismatch", false, "with --reproduce: grant what the recorded run was granted")
	fs.BoolVar(&reproPerm.SkipEraCheck, "skip-era-check", false, "with --reproduce: as the recorded run did")
	fs.BoolVar(&reproPerm.FaultUpstream, "fault-upstream", false, "with --reproduce: grant what the recorded run was granted")
	reproSet = fs
	return fs
}

// permissionsOf reads the switches a recorded spec ran with.
func permissionsOf(s engine.RunSpec) reproducePermissions {
	p := s.Policy
	return reproducePermissions{
		FaultUpstream:  s.Egress.FaultUpstream,
		AllowMutations: p.AllowMutations, AllowDestructive: p.AllowDestructive,
		AllowPlaintextAuth: p.AllowPlaintextAuth, AllowPrivateHosts: p.AllowPrivateHosts,
		AllowResourceMismatch: p.AllowResourceMismatch, SkipEraCheck: p.SkipEraCheck,
	}
}

// permissionMismatch names every switch the plan and the operator disagree
// on, as the flag that would settle it.
func permissionMismatch(plan, given reproducePermissions) []string {
	pairs := []struct {
		flag        string
		plan, given bool
	}{
		{"--allow-mutations", plan.AllowMutations, given.AllowMutations},
		{"--allow-destructive", plan.AllowDestructive, given.AllowDestructive},
		{"--insecure-allow-http-auth", plan.AllowPlaintextAuth, given.AllowPlaintextAuth},
		{"--insecure-allow-private-hosts", plan.AllowPrivateHosts, given.AllowPrivateHosts},
		{"--allow-resource-mismatch", plan.AllowResourceMismatch, given.AllowResourceMismatch},
		{"--skip-era-check", plan.SkipEraCheck, given.SkipEraCheck},
		{"--fault-upstream", plan.FaultUpstream, given.FaultUpstream},
	}
	var out []string
	for _, p := range pairs {
		switch {
		case p.plan && !p.given:
			out = append(out, "the recorded run had "+p.flag+"; pass it to repeat that run")
		case !p.plan && p.given:
			out = append(out, "the recorded run did not have "+p.flag+"; drop it")
		}
	}
	return out
}

// reproduceSpec turns a statement's plan into a spec this operator is
// willing to run, or says why it will not.
func reproduceSpec(st *attest.Statement) (engine.RunSpec, error) {
	spec, err := plannedSpec(st)
	if err != nil {
		return engine.RunSpec{}, err
	}
	if err := reproduceCreds(&spec, st.Predicate.Plan); err != nil {
		return engine.RunSpec{}, err
	}
	spec.Output = engine.OutputSpec{Format: engine.FormatAttestation}
	spec.Gate = nil
	spec.Version = Version
	return spec, nil
}

// plannedSpec is the statement's recorded plan as a run spec, once the
// operator's target, the statement's subject and the plan all agree and the
// permissions the operator gave match the ones the plan had.
func plannedSpec(st *attest.Statement) (engine.RunSpec, error) {
	p := st.Predicate
	if strings.TrimSpace(verifyEndpoint) == "" {
		return engine.RunSpec{}, errors.New("--reproduce contacts the target, so name it with --endpoint (and --transport stdio for a program): the statement alone does not choose what passmcp connects to or runs")
	}
	if !st.Covers(verifyTransport, verifyEndpoint) {
		return engine.RunSpec{}, fmt.Errorf("the statement is about %s %s, not %s %s; refusing to reproduce it against a target it does not cover",
			p.Target.Transport, p.Target.Endpoint, verifyTransport, verifyEndpoint)
	}
	if p.Plan == nil {
		return engine.RunSpec{}, errors.New("the statement records no plan, so there is no run to repeat: it predates recorded plans, or was made from a report that had none")
	}
	spec, err := engine.SpecFromPlan(p.Plan)
	if err != nil {
		return engine.RunSpec{}, fmt.Errorf("the statement's plan is not a passmcp run spec: %w", err)
	}
	// The plan is inside the predicate, not covered by the subject digest,
	// so it is checked against the subject before anything runs.
	planned, transport := spec.Target.Endpoint, "http"
	if spec.Target.Stdio() {
		planned, transport = spec.Target.Describe(), "stdio"
	}
	if transport != p.Target.Transport || planned != p.Target.Endpoint {
		return engine.RunSpec{}, fmt.Errorf("the statement's plan names %s %s but its subject is %s %s; refusing to run a plan that is about a different target",
			transport, planned, p.Target.Transport, p.Target.Endpoint)
	}
	if bad := permissionMismatch(permissionsOf(spec), reproPerm); len(bad) > 0 {
		return engine.RunSpec{}, errors.New(strings.Join(bad, "; "))
	}
	return spec, nil
}

// reproduceCreds gives the spec the credentials the recorded run had: none
// when it sent none, otherwise the operator's, provided they authenticate
// the same way and include every header and parameter it was given.
func reproduceCreds(spec *engine.RunSpec, plan *attestation.Plan) error {
	if plan.Credentials == "none" && len(plan.ByValue) == 0 {
		// The recorded run sent nothing, so this one sends nothing, whatever
		// the environment holds. An API key in a header leaves the mode at
		// none, which is why the by-value list is part of the test.
		spec.Creds = engine.CredSpec{Mode: "none"}
		return nil
	}
	cs, err := credSpec()
	if err != nil {
		return err
	}
	spec.Creds = cs
	cr, err := spec.Credentials()
	if err != nil {
		return err
	}
	if got := string(cr.Effective()); got != plan.Credentials {
		msg := fmt.Sprintf("the recorded run authenticated as %s and this one would be %s; supply credentials with the flags passmcp check takes", plan.Credentials, got)
		if len(plan.ByValue) > 0 {
			msg += " (it was given " + strings.Join(plan.ByValue, ", ") + ")"
		}
		return errors.New(msg)
	}
	// A header or a token parameter does not change the mode, so each
	// one the recorded run was given is asked for by name.
	var missing []string
	for _, b := range plan.ByValue {
		if h, ok := strings.CutPrefix(b, "header "); ok && !hasHeader(cs.Headers, h) {
			missing = append(missing, "--header \""+h+": …\"")
		}
		if k, ok := strings.CutPrefix(b, "param "); ok && !cs.Params.Has(k) {
			missing = append(missing, "--param "+k+"=…")
		}
	}
	if len(missing) > 0 {
		return errors.New("the recorded run was given " + strings.Join(missing, ", ") + "; supply the same to repeat it")
	}
	return nil
}

// reproduce repeats the recorded run and adds the gate on what got worse.
func reproduce(ctx context.Context, st *attest.Statement, v *verification) error {
	spec, err := reproduceSpec(st)
	if err != nil {
		return err
	}
	if spec.Target.Stdio() {
		env := "nothing"
		if len(spec.Target.PassEnv) > 0 {
			env = strings.Join(spec.Target.PassEnv, ", ")
		}
		diag.Infof("reproduce: running %s (forwarding %s)", spec.Target.Describe(), env)
	} else {
		diag.Infof("reproduce: contacting %s", spec.Target.Endpoint)
	}
	res := engine.Run(ctx, spec, nil)
	if res.Report == nil {
		if res.Err != nil {
			return fmt.Errorf("reproduce: %w", res.Err)
		}
		return errors.New("reproduce: the run produced no report")
	}
	again, err := attest.From(res.Report)
	if err != nil {
		return err
	}
	d := attestation.Compare(st, again)
	v.Reproduced = &d

	was, now := st.Predicate, again.Predicate
	detail := "no check got worse"
	if d.Regression() {
		detail = fmt.Sprintf("%d check(s) got worse: %s", len(d.Regressed), changeList(d.Regressed))
	}
	detail += fmt.Sprintf(" (recorded %s by passmcp %s on %s; repeated by passmcp %s on %s)",
		was.RanAt.UTC().Format("2006-01-02T15:04:05Z"), was.Instrument.Version, hostOf(was.Plan),
		now.Instrument.Version, hostOf(now.Plan))
	v.Gates = append(v.Gates, gateResult{Gate: "reproduce", Met: !d.Regression(), Detail: detail})
	if d.Regression() {
		v.OK = false
	}
	return nil
}

// hostOf names the machine a plan was run on.
func hostOf(p *attestation.Plan) string {
	if p == nil {
		return "an unrecorded host"
	}
	h := p.OS + "/" + p.Arch
	if p.Kernel != "" {
		h += " " + p.Kernel
	}
	return h
}

// hasHeader looks a header up the way HTTP does, ignoring case.
func hasHeader(h map[string]string, name string) bool {
	for k := range h {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}
