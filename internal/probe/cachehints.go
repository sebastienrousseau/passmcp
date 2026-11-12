// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"fmt"
	"strings"
	"time"

	"satellion.com/passmcp"
)

// The catalogue budget check says what a catalogue costs to look at. This
// one says whether the server sets the caching hints the 2026-07-28 revision
// defines for list results (SEP-2549).
//
// Under SEP-2549, every complete list result (tools/list, resources/list,
// prompts/list) carries `ttlMs` (integer >= 0; 0 means do not cache) and
// `cacheScope` ("public" or "private"). Malformed values fail; missing or
// half-stated hints on 2026-07-28 warn (noting token cost when the tool
// catalogue exceeds the budget floor), and undeclared list endpoints are
// never penalized. Before 2026-07-28 there are no such fields, so a
// session-era server skips.

const cacheHintFloor = CatalogueTokenBudget

const cacheHintsAdvice = "set ttlMs (integer >= 0; 0 for uncached) and cacheScope (\"public\" or \"private\") " +
	"on every declared list result (SEP-2549). A catalogue without caching hints is re-fetched on every session"

// endpointCacheHints pairs one declared list RPC with the caching hints its
// first page returned.
type endpointCacheHints struct {
	Endpoint string
	Hints    passmcp.CacheHints
}

// checkCacheHints evaluates caching hints for a single list result.
func checkCacheHints(s *Session, hints passmcp.CacheHints, tokens int) []Finding {
	return checkEndpointCacheHints(s, []endpointCacheHints{{Endpoint: "tools/list", Hints: hints}}, tokens)
}

// checkEndpointCacheHints reports what the server's declared list endpoints
// said about caching their responses.
func checkEndpointCacheHints(s *Session, endpoints []endpointCacheHints, tokens int) []Finding {
	c := s.check("catalog.cache_hints", "The catalogue says whether it can be cached")
	if s.Era == nil || s.Era.Era != passmcp.EraStateless {
		return []Finding{c.skip("cache hints on a list result arrived in the 2026-07-28 revision; " +
			"this server speaks an earlier one, where there is nothing to state")}
	}
	if len(endpoints) == 0 {
		return []Finding{c.skip("no declared list endpoint succeeded, so there are no caching hints to inspect")}
	}
	if bad := invalidCacheHint(endpoints); bad != "" {
		return []Finding{c.fail(Minor, bad, cacheHintsAdvice)}
	}
	missing, stated := classifyCacheHints(endpoints)
	if len(missing) == 0 {
		return []Finding{c.pass(renderCacheHints(endpoints))}
	}
	if stated > 0 {
		return []Finding{c.warn("incomplete caching hints (SEP-2549 requires both ttlMs and cacheScope): "+strings.Join(missing, "; "), cacheHintsAdvice)}
	}
	return []Finding{c.warn(unstatedCacheHintsDetail(tokens), cacheHintsAdvice)}
}

func invalidCacheHint(endpoints []endpointCacheHints) string {
	for _, ep := range endpoints {
		if ep.Hints.TTLMs != nil && *ep.Hints.TTLMs < 0 {
			return fmt.Sprintf("%s returned negative ttlMs (%d); SEP-2549 requires an integer >= 0", ep.Endpoint, *ep.Hints.TTLMs)
		}
		if ep.Hints.Scope != "" && ep.Hints.Scope != "public" && ep.Hints.Scope != "private" {
			return fmt.Sprintf("%s returned cacheScope %q; SEP-2549 allows only \"public\" or \"private\"", ep.Endpoint, ep.Hints.Scope)
		}
	}
	return ""
}

func classifyCacheHints(endpoints []endpointCacheHints) (missing []string, stated int) {
	multi := len(endpoints) > 1
	for _, ep := range endpoints {
		if ep.Hints.Stated() {
			stated++
		}
		prefix := ""
		if multi {
			prefix = ep.Endpoint + ": "
		}
		switch {
		case ep.Hints.TTLMs != nil && ep.Hints.Scope != "":
		case ep.Hints.TTLMs != nil:
			missing = append(missing, prefix+"missing cacheScope")
		case ep.Hints.Scope != "":
			missing = append(missing, prefix+"missing ttlMs")
		default:
			missing = append(missing, prefix+"missing ttlMs and cacheScope")
		}
	}
	return missing, stated
}

func renderCacheHints(endpoints []endpointCacheHints) string {
	if len(endpoints) == 1 {
		h := endpoints[0].Hints
		return fmt.Sprintf("cacheable for %s, scope %q", time.Duration(*h.TTLMs)*time.Millisecond, h.Scope)
	}
	parts := make([]string, 0, len(endpoints))
	for _, ep := range endpoints {
		parts = append(parts, fmt.Sprintf("%s: %s (%q)", ep.Endpoint, time.Duration(*ep.Hints.TTLMs)*time.Millisecond, ep.Hints.Scope))
	}
	return strings.Join(parts, "; ")
}

func unstatedCacheHintsDetail(tokens int) string {
	if tokens >= cacheHintFloor {
		return fmt.Sprintf("neither ttlMs nor cacheScope on a 2026-07-28 catalogue of about %d tokens (SEP-2549)", tokens)
	}
	return "neither ttlMs nor cacheScope on 2026-07-28 list results (SEP-2549)"
}
