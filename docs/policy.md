---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  Acceptance policies: a reviewable file that says what your organisation will accept from an MCP server, with exceptions that carry a reason and an expiry date.
---

# Acceptance policies

passmcp can already gate: a failing finding exits 2, and `passmcp verify` takes
`--require`, `--max-fail` and `--min-score`. That is enough for one pipeline.
A policy file is for when it has to be enough for an organisation.

```sh
passmcp check https://mcp.example.com/mcp --policy company.json
passmcp verify attestation.json --policy company.json
```

The same file governs both, so what gates a pipeline and what a gateway
checks months later cannot drift apart.

## Why a file rather than flags

**A flag is not reviewable.** "Why does this server pass?" should not be
answered by reading a CI YAML file, and a change to what the company accepts
should not arrive as a diff to a shell line nobody reviews.

**A flag cannot carry an exception.** Real gates are adopted only if a team
can say *this one check, on this server, for this reason, until this date*.
Without that, the gate gets switched off wholesale on its first inconvenient
morning — so an exemption is a first-class object here, and it is invalid
without a reason and an expiry.

**A flag cannot be refused.** A policy written for a later passmcp, or carrying
a rule this build does not implement, is rejected rather than partly applied.
A policy engine that ignores what it does not understand is a policy engine
that approves things.

## A worked example

```json
{
  "version": 1,
  "name": "platform baseline",
  "description": "What we will route agent traffic to.",

  "must_pass": ["net.tls", "auth.unauthenticated_tools"],
  "must_not_fail": ["catalog.tools.descriptions"],

  "max_fail": 0,
  "max_warn": 5,
  "min_score": 75,
  "min_category_score": { "authorization": 90 },
  "forbid_severity": "major",

  "exemptions": [
    {
      "check": "perf.latency",
      "reason": "This server calls a legacy mainframe; 900ms is the floor.",
      "expires": "2027-06-30",
      "ticket": "PLAT-2214"
    }
  ]
}
```

## The rules

| Key | Holds when |
|---|---|
| `target` | the subject is this server — `{"transport": "http", "endpoint": "…"}`, either field alone is fine |
| `must_pass` | every named check's verdict is `pass` |
| `must_not_fail` | every named check is anything but `fail` — the weaker form, for a check where a warning is tolerable |
| `max_fail`, `max_warn` | at most that many checks failed or warned |
| `min_score` | the total is at least that |
| `min_category_score` | each named category is at least that — how a team says authorization matters more here than the total does |
| `forbid_severity` | no failure at or above `critical`, `major` or `minor`. It is a **threshold**: forbidding `major` forbids `critical` too |

Three refusals are deliberate, and each one is a case where the comfortable
answer would be a pass nobody earned:

- **A check that did not run does not pass.** A run that never made the check
  cannot vouch for it, so `must_pass` on a check outside the phases you ran is
  a failure, not a silence.
- **A missing score is not zero.** A partial run assesses no category and
  carries no score at all; `min_score` reports that it cannot be met, rather
  than failing the server for something that is a fact about the run.
- **An unassessed category is not fine.** Same reasoning, per category.

A numeric rule applies because it is *present*, not because of its value.
`"max_fail": 0` is the strictest form of that rule, and omitting the key is
how you ask for no rule at all.

## Exemptions

An exemption is the difference between a gate a team adopts and a gate a team
disables. It needs three things, and passmcp refuses a policy missing any of
them:

- `check` — one check id.
- `reason` — a sentence a reviewer can disagree with. "Temporary" is the
  reason still in the file three years later, which is why the field is
  required rather than encouraged.
- `expires` — a date, `YYYY-MM-DD`. **The whole difference between an
  exception and a hole is that an exception has a date on it.** The expiry day
  itself is still covered: `2027-06-30` reads as "good through the 30th".

`ticket` is optional and is where a reader goes to find the decision.

An exemption is reported in one of three states, and all three are printed
even when the policy passes — the only moment anybody reads a policy file is
when they are reading its output:

| State | Meaning |
|---|---|
| **applied** | it excused a real failure or warning. The rule it affected says so: `0 checks failed; at most 0 allowed (1 exempted)` — a pass is never silent about how it was reached |
| **unused** | the check it names is no longer failing. Not a failure; this is how an exemption retires, and it has to be visible or the file fills with excuses for problems fixed years ago |
| **expired** | it no longer excuses anything, and the policy fails. The message is about the decision rather than the server, because the reader's next action is to renew it or fix the check |

A check cannot be both required and exempted. That has two answers, and
whichever passmcp picked would surprise half of its readers, so the policy is
refused.

## What a policy changes about the exit code

Without a policy, `passmcp check` exits 2 when any finding failed. **With one,
the policy decides** — it replaces the default rule rather than adding to it.

That is the point of an exemption: a team that has decided, in writing and
with an expiry, that one failing check is acceptable on this server has to get
a pass. Otherwise the exemption changes nothing and the gate gets turned off
instead.

| Code | `passmcp check --policy` | `passmcp verify --policy` |
|---|---|---|
| `0` | the policy is met | the statement is believable and the policy is met |
| `2` | the policy is not met | the statement is believable and the policy is not met |
| `1` | the run could not happen, or the policy could not be enforced | the statement cannot be believed at all |

A policy that cannot be enforced — a misspelled rule, a later version, an
exemption with no date — exits **1**, before the run starts. Nothing was
measured, so there is no verdict about the server to report.

## Where the answer is written

- On stdout after the report, for `--output text` and `--output md`.
- On stderr for every other format, because a gate verdict appended to JSON
  or SARIF would make the document unparseable, and the one reader who needs
  it there is a CI log.
- As `policy.json` in `--report-dir`, beside the evidence it judged. Separate
  from `report.json` on purpose: a report is about the server, and this is
  about a decision somebody made.
