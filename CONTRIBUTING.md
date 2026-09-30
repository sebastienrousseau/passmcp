<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Contributing

passmcp is a compiled Go command-line tool that connects to a remote Model
Context Protocol server with the credentials an operator supplies and
reports, step by step, what it observed. Contributions are welcome.

## Getting Started

1. Fork and clone the repository.
2. Install development dependencies:
   - **Go** at the version the `go` directive in `go.mod` names
   - **Make**
   - **Git**

3. Set up the project hooks (optional but recommended):

   ```bash
   git config core.hooksPath .githooks
   ```

4. Create a branch **from `main`**:

   ```bash
   git checkout main && git pull
   git checkout -b feat/my-change
   ```

   Branch from `main` and open the pull request against `main` — never
   against another branch. Every workflow in this repository filters on
   `pull_request: branches: [main]`, so a PR aimed elsewhere runs no CI
   at all, and GitHub records it as merged with an empty commit range
   once the branch it was stacked on lands. If your change depends on
   work that is still in review, wait for it to merge or fold the two
   into one pull request.

   Version work follows the same rule with a naming convention: a
   release is prepared on `feat/vX.Y.Z`, and pre-1.0 every release bumps
   the patch digit.
5. Make changes.
6. Verify everything passes:

   ```bash
   make format
   make test
   make build
   ```

7. Commit, push, and open a pull request.

## Commits

**Sign your commits cryptographically and add a DCO sign-off trailer.**
Both are required — signing proves who authored the commit; the DCO
sign-off asserts you have the right to contribute the change under the
project licence.

### Cryptographic signing

```bash
# Enable signing once (SSH or GPG both accepted):
git config --global commit.gpgsign true
```

Need a signing key? Follow
[GitHub's guide to signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

### Developer Certificate of Origin (DCO)

Every commit you author must include a `Signed-off-by:` trailer matching
the commit author. Merge commits are exempt: a merge introduces no
authored content, so there is nothing for its author to certify, and
updating a branch from `main` — which this repository requires before a
merge — produces one that GitHub wrote rather than you. The full text of the DCO is at
<https://developercertificate.org>; adding the trailer certifies that
you agree to it. Enforced by the DCO workflow on every PR.

```bash
# Sign off a single commit:
git commit -s -m "your message"

# Amend the most recent commit to add a sign-off you forgot:
git commit --amend --signoff

# Retroactively sign off a range of commits before your PR base:
git rebase --signoff <base-sha>
```

Configure `git commit -s` as your default by aliasing it locally
(`git config --global alias.ci 'commit -s'`) or by using
`git config --global format.signoff true` if your git version supports it.

### Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/) with an
imperative subject: `feat(probe): add resource read timing`, not
`Added timing`.

## Pull Request Checklist

- [ ] `make test` passes
- [ ] `make test-race` passes
- [ ] `make build` succeeds
- [ ] A finding, flag or output change is covered by a test against a
      fake server (see `internal/probe/fake_test.go`) — never a live one
- [ ] README updated if behaviour changed
- [ ] `CHANGELOG.md` has an entry under `## [Unreleased]`
- [ ] All commits are signed (`git log --show-signature`)
- [ ] All commits carry a DCO sign-off (`git commit -s`)

## Code review

Every change reaches `main` through a pull request, including the
maintainer's own. Branch protection on `main` refuses a direct push, a
force push and an unsigned commit, for administrators too.

### Who reviews

The maintainer listed in [MAINTAINERS.md](MAINTAINERS.md) reviews every
pull request; `.github/CODEOWNERS` routes each one to them. The first
review comes within seven days, as MAINTAINERS.md states, and only the
maintainer merges.

passmcp has one maintainer, so the maintainer's own pull requests have
no second human reviewer. They get the same required checks and are
held to the same list below; GOVERNANCE.md records that bus factor and
how a co-maintainer is added.

### How a pull request is reviewed

1. **The required checks pass.** Branch protection will not merge until
   every one is green: the test matrix on Linux, macOS and Windows, the
   race detector, the 85% coverage gate, lint, fuzz smoke, the install
   contract, the release configuration, the repository checks (commit
   messages among them), the vulnerability and dependency scans, secret
   scanning, licence headers, the Markdown, spelling and link checks,
   the DCO check, and the check that the pull request targets `main`.
   [DEVELOPMENT.md](DEVELOPMENT.md#reproducing-every-ci-gate) has the
   local command for each.
2. **The branch is current with `main`.** Protection requires it, so a
   change is tested against what it will merge into.
3. **The reviewer reads the change** against the list below and leaves
   comments. Every conversation must be resolved before the merge.
4. **The maintainer merges.** Merge commits are allowed; history on
   `main` is never rewritten.

### What the reviewer checks

- **Tests against a fake server.** New or changed behaviour has a test
  that fails without the change, run against an `httptest` fake
  (`internal/probe/fake_test.go`, `testserver_test.go`). A hard-to-reach
  branch gets a new knob on the fake, never a live server.
- **Findings pass only on evidence.** A check returns `pass` only after
  a request that showed the property, and cites it; a failed or absent
  request is never a pass
  ([ADR 0002](docs/adr/0002-findings-cite-requests.md)). `check.done`
  records an unevidenced pass as info, and the probe suite fails on one;
  a check that judges an earlier response is declared in
  `internal/probe/evidence.go` with where its evidence is. A blocked phase
  makes later phases skipped, not passed.
- **Secrets stay redacted.** A new credential kind registers its secret
  with the recorder before the first request, and a new report or
  telemetry field that carries server or credential text is bounded and
  passes through the `Redactor`
  ([ADR 0003](docs/adr/0003-structural-redaction-at-the-recorder.md)).
- **Read-only stays the default.** Nothing makes passmcp invoke a tool
  without `readOnlyHint: true` unless the operator opted in, and the
  unauthenticated probes keep using the credential-free transport
  ([ADR 0004](docs/adr/0004-read-only-by-default.md),
  [ADR 0001](docs/adr/0001-bare-transport-for-unauthenticated-probes.md)).
- **Stdout and stderr stay separate.** Stdout carries only the selected
  `--output` format; diagnostics go to stderr through `internal/diag`.
- **Every file has its SPDX header** (`make spdx-check`).
- **`CHANGELOG.md` has an entry** under `## [Unreleased]` for anything a
  user would notice.
- **A new dependency is justified** in the commit message and recorded
  in `SBOM.md` (`make sbom-check`).
- **Commits are signed, signed off, and Conventional.**

### What makes a change acceptable

A change is merged when the required checks are green, the list above
holds, every review conversation is resolved, and it does one thing: a
structural or documentation cleanup lands separately from a behaviour
change. A change that weakens a safety default, makes a finding pass
without evidence, or breaks what the README's stability guarantees
promise is declined, and the reason is given in the pull request.

## Code Style

- Use standard Go formatting (`gofmt -w .`).
- Ensure all exported functions and types are documented.
- Follow idiomatic Go guidelines.
- Results go to stdout in the selected `--output` format; diagnostics go
  to stderr through `internal/diag`. A `fmt.Println` on a diagnostic
  path is a bug.
- Anything a server sends is untrusted. New report or telemetry fields
  that carry server-supplied or credential-bearing text must pass
  through the recorder's `Redactor`.
