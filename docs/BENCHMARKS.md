---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  What passmcp's own work costs: report rendering times and allocations, the binary-size budget, and which budgets CI gates.
---

# Benchmarks

A run's wall clock belongs to the server. Roughly fifty requests,
deliberately throttled, means the time you wait is almost entirely
somebody else's latency. Rendering the report is passmcp's own work, and it
is the part worth measuring.

## Rendering

A 200-tool report, two findings per tool, rendered in each format:

| Format | Time per render | Allocations | Bytes allocated |
| :--- | ---: | ---: | ---: |
| JSON | 0.31 ms | 7 | 0.3 KB |
| Markdown | 0.60 ms | 2,873 | 271 KB |
| Text | 0.89 ms | 7,039 | 311 KB |
| HTML | 1.83 ms | 10,014 | 371 KB |

Measured 26 Sep 2026 on an Apple A18 Pro (darwin/arm64), go1.27.1, as
the median of three runs of:

```bash
go test ./internal/report/ -run '^$' -bench Render -benchmem -count 3
```

Allocation counts are deterministic and reproduce exactly. Times vary
with the machine and its load; a number without the machine it was
measured on is marketing.

HTML is the most expensive and reasonably so: it is the only renderer
that escapes every string on the way out, and every string in a report
came from a server nobody vetted.

## What CI gates, and what it does not

- **Binary size**: 18 MiB (`make perf`, `BINARY_BUDGET_MIB`). A static
  binary a security team can approve in an afternoon is the product, and
  the way that stops being true is one dependency at a time.
- **Allocation ceilings** per renderer, and a check that rendering scales
  linearly with the number of findings (`internal/report/perf_test.go`).
  An accidental quadratic passes every correctness test and is unusable
  on the catalogue sizes that make a diagnostic worth running.

Wall-clock times are published here and deliberately not gated. A time
limit on a shared CI runner is a flaky gate, and a flaky gate teaches
people to re-run the build until it is green.
