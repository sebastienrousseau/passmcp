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
