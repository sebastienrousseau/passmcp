// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"satellion.com/passmcp/diagnostics"
	"satellion.com/passmcp/internal/telemetry"
	"satellion.com/passmcp/transport"
)

// ToolPerf is the latency profile of one tool over repeated calls.
type ToolPerf struct {
	Name    string `json:"name"`
	Samples int    `json:"samples"`
	Cold    Millis `json:"cold_ms"`
	P50     Millis `json:"p50_ms"`
	P95     Millis `json:"p95_ms"`
	Max     Millis `json:"max_ms"`
	Errors  int    `json:"errors"`
}

// ConcurrencyResult is the outcome of a parallel burst.
type ConcurrencyResult struct {
	Tool        string  `json:"tool"`
	Workers     int     `json:"workers"`
	Calls       int     `json:"calls"`
	OK          int     `json:"ok"`
	Errors      int     `json:"errors"`
	RateLimited int     `json:"rate_limited"`
	RetryAfter  bool    `json:"retry_after_header"`
	Wall        Millis  `json:"wall_ms"`
	Throughput  float64 `json:"calls_per_second"`
	P50         Millis  `json:"p50_ms"`
	P95         Millis  `json:"p95_ms"`
	Max         Millis  `json:"max_ms"`
}

// PerfResult is the performance phase output.
type PerfResult struct {
	Ping        *ToolPerf          `json:"ping,omitempty"`
	Tools       []ToolPerf         `json:"tools,omitempty"`
	Concurrency *ConcurrencyResult `json:"concurrency,omitempty"`
}

// perfContext labels a performance-phase request for telemetry.
type perfContext func(label string) context.Context

// phasePerformance measures repeat-call latency for tools that succeeded
// and runs a bounded parallel burst.
func phasePerformance(ctx context.Context, s *Session) []Finding {
	s.Perf = &PerfResult{}
	pctx := perfContext(func(label string) context.Context { return telemetry.WithPhase(ctx, "performance", label) })
	limiter := diagnostics.NewLimiter(s.Opts.RPS, 1)

	// ping baseline
	out, ok := perfPing(ctx, s, limiter, pctx)
	if !ok {
		return out
	}

	// repeat successful, allowed tools
	candidates, found, ok := perfTools(ctx, s, limiter, pctx)
	out = append(out, found...)
	if !ok {
		return out
	}

	// concurrency burst on the fastest successful tool (or ping)
	if s.Opts.Concurrency > 1 {
		out = append(out, perfBurst(ctx, s, limiter, pctx, candidates)...)
	}
	// keep the slice sorted for stable reports
	sort.Slice(s.Perf.Tools, func(i, j int) bool { return s.Perf.Tools[i].Name < s.Perf.Tools[j].Name })
	return out
}

// perfPing measures the liveness round trip. It reports false when the
// limiter gave up, which ends the phase with the findings so far.
func perfPing(ctx context.Context, s *Session, limiter *diagnostics.Limiter, pctx perfContext) ([]Finding, bool) {
	var lat diagnostics.Latencies
	live, liveParams := s.liveness()
	tp := ToolPerf{Name: live, Samples: s.Opts.Samples}
	for i := 0; i < s.Opts.Samples; i++ {
		if err := limiter.Wait(ctx); err != nil {
			return nil, false
		}
		t0 := time.Now()
		if err := s.Client.Call(pctx(live), live, liveParams, nil); err != nil {
			tp.Errors++
			continue
		}
		d := time.Since(t0)
		if i == 0 {
			tp.Cold = Millis(d)
		}
		lat.Add(d)
	}
	tp.P50, tp.P95, tp.Max = Millis(lat.Percentile(50)), Millis(lat.Percentile(95)), Millis(lat.Max())
	s.Perf.Ping = &tp
	c := s.check("performance.ping", "Round-trip baseline ("+live+")")
	switch {
	case tp.Errors == s.Opts.Samples:
		return []Finding{c.fail(Major, "every "+live+" failed", "")}, true
	case tp.P50.Duration() > 500*time.Millisecond:
		return []Finding{c.warn(fmt.Sprintf("p50 %s p95 %s over %d samples", ms(tp.P50), ms(tp.P95), lat.Len()), "a slow no-op round trip points at the transport or auth layer, not the tools")}, true
	default:
		return []Finding{c.pass(fmt.Sprintf("p50 %s p95 %s max %s over %d samples", ms(tp.P50), ms(tp.P95), ms(tp.Max), lat.Len()))}, true
	}
}

// perfTools repeats the tools that succeeded in the execution phase and
// reports their latency and warm-up. It returns the tools it repeated, which
// the burst draws its target from, and false when the limiter gave up.
func perfTools(ctx context.Context, s *Session, limiter *diagnostics.Limiter, pctx perfContext) ([]ToolResult, []Finding, bool) {
	var succeeded []ToolResult
	for _, r := range s.ToolResults {
		if r.Executed && r.OK {
			succeeded = append(succeeded, r)
		}
	}
	candidates := repeatCandidates(succeeded, s.Opts.Endpoint+"\x00"+s.command())
	if len(candidates) == 0 {
		return candidates, []Finding{s.check("performance.tools", "Tool latency profile").skip("no tool completed successfully in the execution phase")}, true
	}
	var slow []string
	var allLat diagnostics.Latencies
	for _, r := range candidates {
		tp, ok := repeatTool(ctx, s, limiter, pctx, r, &allLat)
		if !ok {
			return candidates, nil, false
		}
		s.Perf.Tools = append(s.Perf.Tools, tp)
		if tp.P95.Duration() > 2*time.Second {
			slow = append(slow, fmt.Sprintf("%s (p95 %.1fs)", r.Name, tp.P95.Duration().Seconds()))
		}
	}
	out := []Finding{perfToolsFinding(s, len(candidates), len(succeeded), slow, &allLat)}
	return candidates, append(out, warmupFinding(s)), true
}

// repeatTool calls one tool Samples times and profiles the calls that
// succeeded, adding each to allLat as well. It reports false when the
// limiter gave up.
func repeatTool(ctx context.Context, s *Session, limiter *diagnostics.Limiter, pctx perfContext, r ToolResult, allLat *diagnostics.Latencies) (ToolPerf, bool) {
	var lat diagnostics.Latencies
	tp := ToolPerf{Name: r.Name, Samples: s.Opts.Samples, Cold: r.Duration}
	for i := 0; i < s.Opts.Samples; i++ {
		if err := limiter.Wait(ctx); err != nil {
			return tp, false
		}
		cctx, cancel := context.WithTimeout(pctx("repeat "+r.Name), s.Opts.CallTimeout)
		t0 := time.Now()
		res, err := s.Client.CallTool(cctx, r.Name, r.Arguments)
		d := time.Since(t0)
		cancel()
		if err != nil || res.IsError {
			tp.Errors++
			continue
		}
		lat.Add(d)
		allLat.Add(d)
	}
	tp.P50, tp.P95, tp.Max = Millis(lat.Percentile(50)), Millis(lat.Percentile(95)), Millis(lat.Max())
	return tp, true
}

// perfToolsFinding is the latency profile across every repeated tool.
func perfToolsFinding(s *Session, repeated, succeeded int, slow []string, allLat *diagnostics.Latencies) Finding {
	c := s.check("performance.tools", "Tool latency profile")
	summary := fmt.Sprintf("%d tools × %d samples: p50 %s p95 %s max %s", repeated, s.Opts.Samples, ms(allLat.Percentile(50)), ms(allLat.Percentile(95)), ms(allLat.Max()))
	if repeated < succeeded {
		summary = fmt.Sprintf("%d of %d tools (the %d slowest and %d chosen by a seed from the target) × %d samples: p50 %s p95 %s max %s",
			repeated, succeeded, repeatSlowest, repeated-repeatSlowest, s.Opts.Samples,
			ms(allLat.Percentile(50)), ms(allLat.Percentile(95)), ms(allLat.Max()))
	}
	if len(slow) > 0 {
		return c.warn(summary+"; slow: "+strings.Join(slow, ", "), "p95 above 2s makes agents time out or retry; look at what those tools do on each call (indexing, unbounded scans) and cache or bound it")
	}
	return c.pass(summary)
}

// warmupFinding compares each repeated tool's first call with its median.
func warmupFinding(s *Session) Finding {
	c := s.check("performance.warmup", "Cold vs warm call")
	var coldDelta []string
	for _, tp := range s.Perf.Tools {
		if tp.P50 > 0 && tp.Cold > 4*tp.P50 && tp.Cold.Duration() > 500*time.Millisecond {
			coldDelta = append(coldDelta, fmt.Sprintf("%s cold %s vs p50 %s", tp.Name, ms(tp.Cold), ms(tp.P50)))
		}
	}
	if len(coldDelta) > 0 {
		return c.info("first call much slower: " + fmt.Sprint(coldDelta) + " (lazy indexing or cache warm-up)")
	}
	return c.pass("no significant warm-up penalty")
}

// perfBurst runs the parallel burst on the fastest tool that never failed
// its repeats, or on the liveness call when there is none, and reports it.
func perfBurst(ctx context.Context, s *Session, limiter *diagnostics.Limiter, pctx perfContext, candidates []ToolResult) []Finding {
	tool, args := burstTarget(s, candidates)
	workers := s.Opts.Concurrency
	per := s.Opts.Samples
	cr := ConcurrencyResult{Tool: tool, Workers: workers, Calls: workers * per}
	if tool == "" {
		cr.Tool = s.livenessName()
	}
	lat := runBurst(ctx, s, limiter, pctx, &cr, tool, args)
	if cr.Wall > 0 {
		cr.Throughput = float64(cr.OK+cr.Errors+cr.RateLimited) / cr.Wall.Duration().Seconds()
	}
	cr.P50, cr.P95, cr.Max = Millis(lat.Percentile(50)), Millis(lat.Percentile(95)), Millis(lat.Max())
	s.Perf.Concurrency = &cr
	return burstFindings(s, &cr, workers, per)
}

// burstTarget picks the fastest repeated tool with no errors, and the
// arguments it succeeded with. An empty name means the liveness call.
func burstTarget(s *Session, candidates []ToolResult) (string, map[string]any) {
	tool := ""
	var args map[string]any
	best := Millis(1<<62 - 1)
	for _, tp := range s.Perf.Tools {
		if tp.Errors == 0 && tp.P50 < best {
			best, tool = tp.P50, tp.Name
		}
	}
	for _, r := range candidates {
		if r.Name == tool {
			args = r.Arguments
		}
	}
	return tool, args
}

// runBurst runs cr.Workers workers of Samples calls each and tallies them
// into cr, including the wall time. It returns the successful calls'
// latencies.
func runBurst(ctx context.Context, s *Session, limiter *diagnostics.Limiter, pctx perfContext, cr *ConcurrencyResult, tool string, args map[string]any) *diagnostics.Latencies {
	var mu sync.Mutex
	var lat diagnostics.Latencies
	var wg sync.WaitGroup
	wall := time.Now()
	for w := 0; w < cr.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < s.Opts.Samples; i++ {
				if !s.Opts.AllowLoad {
					if err := limiter.Wait(ctx); err != nil {
						return
					}
				}
				d, isErr, err := burstCall(pctx("burst "+cr.Tool), s, tool, args)
				mu.Lock()
				tallyBurst(cr, &lat, d, isErr, err)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	cr.Wall = Millis(time.Since(wall))
	return &lat
}

// burstCall makes one burst call: the tool, or the liveness call when tool
// is empty. It reports the call's duration and whether the tool answered
// with an error result.
func burstCall(ctx context.Context, s *Session, tool string, args map[string]any) (time.Duration, bool, error) {
	cctx, cancel := context.WithTimeout(ctx, s.Opts.CallTimeout)
	t0 := time.Now()
	var err error
	var isErr bool
	if tool == "" {
		lm, lp := s.liveness()
		err = s.Client.Call(cctx, lm, lp, nil)
	} else {
		var res *transportCallResult
		res, err = callTool(cctx, s, tool, args)
		isErr = res != nil && res.IsError
	}
	d := time.Since(t0)
	cancel()
	return d, isErr, err
}

// tallyBurst files one burst call as rate-limited, failed or ok. The caller
// holds the lock that guards cr and lat.
func tallyBurst(cr *ConcurrencyResult, lat *diagnostics.Latencies, d time.Duration, isErr bool, err error) {
	var he *transport.HTTPStatusError
	switch {
	case err != nil && asHTTP(err, &he) && he.StatusCode == http.StatusTooManyRequests:
		cr.RateLimited++
		if he.Header.Get("Retry-After") != "" {
			cr.RetryAfter = true
		}
	case err != nil || isErr:
		cr.Errors++
	default:
		cr.OK++
		lat.Add(d)
	}
}

// burstFindings reports the burst, and whether it was throttled or drew
// no rate limiting.
func burstFindings(s *Session, cr *ConcurrencyResult, workers, per int) []Finding {
	var out []Finding
	c := s.check("performance.concurrency", fmt.Sprintf("Parallel burst (%d workers × %d calls on %s)", workers, per, cr.Tool))
	detail := fmt.Sprintf("%d ok, %d errors, %d rate-limited in %s (%.1f calls/s); p50 %s p95 %s", cr.OK, cr.Errors, cr.RateLimited, ms(cr.Wall), cr.Throughput, ms(cr.P50), ms(cr.P95))
	switch {
	case cr.Errors > 0:
		out = append(out, c.fail(Major, detail, "errors under modest concurrency indicate shared-state or connection-handling bugs"))
	case cr.RateLimited > 0 && !cr.RetryAfter:
		out = append(out, c.warn(detail+"; 429 without Retry-After", "send Retry-After so clients back off correctly"))
	case cr.RateLimited > 0:
		out = append(out, c.pass(detail+"; 429 with Retry-After"))
	default:
		out = append(out, c.pass(detail))
	}
	if !s.Opts.AllowLoad && s.Opts.RPS > 0 {
		out = append(out, s.check("performance.throttle", "Burst was throttled").info(fmt.Sprintf("capped at %.0f req/s by passmcp; pass --allow-load to test rate limiting for real", s.Opts.RPS)))
	}
	if s.Opts.AllowLoad && cr.RateLimited == 0 {
		out = append(out, s.check("performance.rate_limit", "Server rate-limits an unthrottled burst").warn("no 429 observed", "if this is a shared tenant, consider per-client rate limits"))
	}
	return out
}

type transportCallResult struct{ IsError bool }

func callTool(ctx context.Context, s *Session, name string, args map[string]any) (*transportCallResult, error) {
	res, err := s.Client.CallTool(ctx, name, args)
	if err != nil {
		return nil, err
	}
	return &transportCallResult{IsError: res.IsError}, nil
}

// asHTTP reports whether err wraps an HTTP status error, and binds it.
// errors.As already walks the chain, so there is nothing to unwrap by hand.
func asHTTP(err error, target **transport.HTTPStatusError) bool {
	return errors.As(err, target)
}

// The repeat pass is serial and throttled, so its cost grows with the
// catalogue: fifty tools at five samples and two requests a second is a
// two-minute floor before anything else runs. repeatSlowest and
// repeatSampled bound it. The slowest are always kept, because they are
// what the latency finding is about; the rest are a sample.
const (
	repeatSlowest = 5
	repeatSampled = 5
)

// repeatCandidates picks the tools the performance phase repeats: all of
// them when there are few, otherwise the slowest by their execution-phase
// call and a sample of the rest.
//
// The sample is seeded from the target, not the clock, so two runs against
// the same server repeat the same tools and their latency figures compare.
// The picks come back in their original order.
func repeatCandidates(all []ToolResult, seed string) []ToolResult {
	if len(all) <= repeatSlowest+repeatSampled {
		return all
	}
	idx := make([]int, len(all))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		if all[idx[a]].Duration != all[idx[b]].Duration {
			return all[idx[a]].Duration > all[idx[b]].Duration
		}
		return all[idx[a]].Name < all[idx[b]].Name
	})
	keep := map[int]bool{}
	for _, i := range idx[:repeatSlowest] {
		keep[i] = true
	}
	rest := append([]int(nil), idx[repeatSlowest:]...)
	sort.Slice(rest, func(a, b int) bool { return all[rest[a]].Name < all[rest[b]].Name })
	h := fnv.New64a()
	_, _ = h.Write([]byte(seed))
	rng := rand.New(rand.NewPCG(h.Sum64(), 0)) // #nosec G404 -- a sample, not a secret
	rng.Shuffle(len(rest), func(a, b int) { rest[a], rest[b] = rest[b], rest[a] })
	for _, i := range rest[:repeatSampled] {
		keep[i] = true
	}
	out := make([]ToolResult, 0, len(keep))
	for i, r := range all {
		if keep[i] {
			out = append(out, r)
		}
	}
	return out
}
