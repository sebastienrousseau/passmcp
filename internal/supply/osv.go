// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package supply

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// A bill of materials says what a server is made of. The question a
// reviewer asks next is whether any of it is known to be broken, and OSV
// answers it for every ecosystem read here, from one API.
//
// It is the only part of passmcp sbom that touches the network, so it is
// off unless the operator asks, and what it sends is stated before it is
// sent: package URLs, and nothing else — no hashes, no paths, no project
// name. Components that did not come from a public registry are never
// sent at all. No public database can know them, and a name like
// corp.example.com/billing is the kind of thing a company keeps to
// itself. ADR 0006 records the boundary this sits inside.

// DefaultOSVEndpoint is the public OSV API. An operator whose package
// names are confidential points --osv-url at a mirror instead.
const DefaultOSVEndpoint = "https://api.osv.dev"

const (
	// osvBatch is the API's limit on queries per request.
	osvBatch = 1000
	// osvPages bounds how many continuation rounds are followed. The
	// endpoint is the operator's choice and may be a mirror; one that
	// hands out page tokens forever is stopped, not obeyed.
	osvPages = 32
	// osvMaxBody bounds one response. The largest real batch answers
	// are a few hundred kilobytes.
	osvMaxBody = 32 << 20
	// osvDetailWorkers bounds concurrent detail requests.
	osvDetailWorkers = 8
	// osvSummaryMax bounds the text taken from an advisory, which is
	// written by whoever filed it.
	osvSummaryMax = 500
)

// BOMVulnerability is one advisory affecting one or more components.
type BOMVulnerability struct {
	BOMRef      string         `json:"bom-ref,omitempty"`
	ID          string         `json:"id"`
	Source      *BOMSource     `json:"source,omitempty"`
	References  []BOMReference `json:"references,omitempty"`
	Ratings     []BOMRating    `json:"ratings,omitempty"`
	Description string         `json:"description,omitempty"`
	Published   string         `json:"published,omitempty"`
	Updated     string         `json:"updated,omitempty"`
	Affects     []BOMAffect    `json:"affects"`
}

// BOMSource names where an advisory came from.
type BOMSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// BOMReference is the same vulnerability under another identifier.
type BOMReference struct {
	ID     string    `json:"id"`
	Source BOMSource `json:"source"`
}

// BOMRating is a severity, as a CVSS vector or as the database's own word.
type BOMRating struct {
	Severity string `json:"severity,omitempty"`
	Method   string `json:"method,omitempty"`
	Vector   string `json:"vector,omitempty"`
}

// BOMAffect points an advisory at a component.
type BOMAffect struct {
	Ref string `json:"ref"`
}

// OSV looks up advisories for a document's components.
type OSV struct {
	// Endpoint is the API root; DefaultOSVEndpoint when empty.
	Endpoint string
	// Client makes the requests; a client with a timeout when nil.
	Client *http.Client
}

// Queryable reports how many of a document's components a lookup would
// send, so the caller can say so before it happens.
func Queryable(doc *BOM) int {
	return len(queryable(doc))
}

// queryable lists the package URLs a lookup may send, each once.
func queryable(doc *BOM) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range doc.Components {
		// A purl with no version cannot be matched, and one from a path
		// or a private module must not be sent.
		if c.private || c.PURL == "" || !strings.Contains(c.PURL, "@") || seen[c.PURL] {
			continue
		}
		seen[c.PURL] = true
		out = append(out, c.PURL)
	}
	sort.Strings(out)
	return out
}

// Annotate adds every advisory that affects a component to the document,
// and records in its metadata where the answer came from.
//
// A lookup that fails fails the call. A document that silently lacked
// its vulnerabilities would read as a clean bill of health.
func (o OSV) Annotate(ctx context.Context, doc *BOM) error {
	endpoint := strings.TrimRight(o.Endpoint, "/")
	if endpoint == "" {
		endpoint = DefaultOSVEndpoint
	}
	if err := checkOSVEndpoint(endpoint); err != nil {
		return err
	}
	client := o.Client
	if client == nil {
		client = defaultOSVClient()
	}

	purls := queryable(doc)
	ids, err := o.batch(ctx, client, endpoint, purls)
	if err != nil {
		return err
	}
	details, err := o.details(ctx, client, endpoint, ids)
	if err != nil {
		return err
	}

	doc.Vulnerabilities = doc.Vulnerabilities[:0]
	doc.Vulnerabilities = append(doc.Vulnerabilities, advisories(doc, ids, details)...)

	doc.Metadata.Properties = append(doc.Metadata.Properties,
		BOMProperty{Name: "passmcp:osv-endpoint", Value: endpoint},
		BOMProperty{Name: "passmcp:osv-queried", Value: fmt.Sprintf("%d", len(purls))},
		BOMProperty{Name: "passmcp:osv-advisories", Value: fmt.Sprintf("%d", len(doc.Vulnerabilities))},
	)
	return nil
}

// defaultOSVClient is the client used when the caller supplies none: a
// timeout, and no redirect away from the host the operator named.
func defaultOSVClient() *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		// A redirect to another host would send the package list
		// somewhere the operator did not name.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Host != via[0].URL.Host {
				return fmt.Errorf("supply: OSV endpoint redirected to %s; not following it to another host", req.URL.Host)
			}
			if len(via) >= 5 {
				return errors.New("supply: OSV endpoint redirected too many times")
			}
			return nil
		},
	}
}

// advisories turns the lookup's answers into the document's vulnerability
// list: one entry per advisory, pointed at every component it affects,
// sorted by id and by component reference.
func advisories(doc *BOM, ids map[string][]string, details map[string]osvDetail) []BOMVulnerability {
	// Component purl -> bom-ref, to point each advisory at what it affects.
	refs := map[string][]string{}
	for _, c := range doc.Components {
		refs[c.PURL] = append(refs[c.PURL], c.BOMRef)
	}
	byID := map[string]*BOMVulnerability{}
	for purl, list := range ids {
		for _, id := range list {
			d, ok := details[id]
			if !ok {
				// Withdrawn: an advisory its own database retracted is
				// not a vulnerability.
				continue
			}
			v := byID[id]
			if v == nil {
				v = d.vulnerability()
				byID[id] = v
			}
			for _, r := range refs[purl] {
				v.Affects = append(v.Affects, BOMAffect{Ref: r})
			}
		}
	}
	var out []BOMVulnerability
	for _, v := range byID {
		sort.Slice(v.Affects, func(i, j int) bool { return v.Affects[i].Ref < v.Affects[j].Ref })
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// checkOSVEndpoint accepts https anywhere, and plain http only to this
// machine: a package list is not secret, but it is not something to send
// across a network in the clear either, and a mirror worth trusting
// speaks TLS.
func checkOSVEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return fmt.Errorf("supply: OSV endpoint %q is not a URL", endpoint)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if ip := net.ParseIP(u.Hostname()); (ip != nil && ip.IsLoopback()) || u.Hostname() == "localhost" {
			return nil
		}
		return fmt.Errorf("supply: OSV endpoint %q is plain http to another machine; use https", endpoint)
	}
	return fmt.Errorf("supply: OSV endpoint %q is not an http(s) URL", endpoint)
}

type osvQuery struct {
	Package   osvPackage `json:"package"`
	PageToken string     `json:"page_token,omitempty"`
}

type osvPackage struct {
	PURL string `json:"purl"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

// batch asks which advisories affect each package URL, following page
// tokens for packages with more advisories than fit in one answer.
func (o OSV) batch(ctx context.Context, client *http.Client, endpoint string, purls []string) (map[string][]string, error) {
	out := map[string][]string{}
	pending := make([]osvQuery, 0, len(purls))
	for _, p := range purls {
		pending = append(pending, osvQuery{Package: osvPackage{PURL: p}})
	}
	for round := 0; len(pending) > 0; round++ {
		if round == osvPages {
			return nil, fmt.Errorf("supply: OSV was still paginating after %d rounds; refusing to follow further", osvPages)
		}
		var next []osvQuery
		for start := 0; start < len(pending); start += osvBatch {
			chunk := pending[start:min(start+osvBatch, len(pending))]
			more, err := osvQueryChunk(ctx, client, endpoint, chunk, out)
			if err != nil {
				return nil, err
			}
			next = append(next, more...)
		}
		pending = next
	}
	for p := range out {
		out[p] = dedupe(out[p])
	}
	return out, nil
}

// osvQueryChunk sends one batch of queries, records each advisory id
// against its package URL in out, and returns the continuation queries for
// packages whose answer was paginated.
func osvQueryChunk(ctx context.Context, client *http.Client, endpoint string, chunk []osvQuery, out map[string][]string) ([]osvQuery, error) {
	body, err := json.Marshal(map[string]any{"queries": chunk})
	if err != nil {
		return nil, err
	}
	var resp osvBatchResponse
	if err := osvDo(ctx, client, http.MethodPost, endpoint+"/v1/querybatch", body, &resp); err != nil {
		return nil, err
	}
	if len(resp.Results) != len(chunk) {
		// Results are matched to queries by position, so a
		// short answer would attach advisories to the wrong
		// packages.
		return nil, fmt.Errorf("supply: OSV answered %d queries with %d results", len(chunk), len(resp.Results))
	}
	var next []osvQuery
	for i, r := range resp.Results {
		q := chunk[i]
		for _, v := range r.Vulns {
			if v.ID != "" {
				out[q.Package.PURL] = append(out[q.Package.PURL], v.ID)
			}
		}
		if r.NextPageToken != "" {
			next = append(next, osvQuery{Package: q.Package, PageToken: r.NextPageToken})
		}
	}
	return next, nil
}

// osvDetail is the part of an advisory this reads.
type osvDetail struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Aliases   []string `json:"aliases"`
	Published string   `json:"published"`
	Modified  string   `json:"modified"`
	Withdrawn string   `json:"withdrawn"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// details fetches each advisory once, a bounded number at a time.
// Withdrawn advisories are left out of the result.
func (o OSV) details(ctx context.Context, client *http.Client, endpoint string, ids map[string][]string) (map[string]osvDetail, error) {
	var all []string
	for _, list := range ids {
		all = append(all, list...)
	}
	all = dedupe(all)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	f := &detailFetch{out: map[string]osvDetail{}, cancel: cancel}
	var wg sync.WaitGroup
	work := make(chan string)
	for range min(osvDetailWorkers, len(all)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.fetch(ctx, client, endpoint, work)
		}()
	}
feed:
	for _, id := range all {
		select {
		case work <- id:
		case <-ctx.Done():
			break feed
		}
	}
	close(work)
	wg.Wait()
	if f.first != nil {
		return nil, f.first
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return f.out, nil
}

// detailFetch is the state the detail workers share: the advisories
// fetched so far, and the first error, which cancels the rest.
type detailFetch struct {
	mu     sync.Mutex
	out    map[string]osvDetail
	first  error
	cancel context.CancelFunc
}

// fetch is one detail worker: it takes ids from work until it is closed,
// keeping every advisory that has not been withdrawn.
func (f *detailFetch) fetch(ctx context.Context, client *http.Client, endpoint string, work <-chan string) {
	for id := range work {
		var d osvDetail
		err := osvDo(ctx, client, http.MethodGet, endpoint+"/v1/vulns/"+url.PathEscape(id), nil, &d)
		f.mu.Lock()
		switch {
		case err != nil && f.first == nil:
			f.first = err
			f.cancel()
		case err == nil && d.Withdrawn == "":
			if d.ID == "" {
				d.ID = id
			}
			f.out[id] = d
		}
		f.mu.Unlock()
	}
}

// vulnerability renders an advisory in CycloneDX's terms.
func (d osvDetail) vulnerability() *BOMVulnerability {
	v := &BOMVulnerability{
		BOMRef:      "osv:" + d.ID,
		ID:          d.ID,
		Source:      &BOMSource{Name: "OSV", URL: "https://osv.dev/vulnerability/" + url.PathEscape(d.ID)},
		Description: truncateText(d.Summary, osvSummaryMax),
		Published:   d.Published,
		Updated:     d.Modified,
		Affects:     []BOMAffect{},
	}
	for _, a := range dedupe(d.Aliases) {
		v.References = append(v.References, BOMReference{
			ID:     a,
			Source: BOMSource{Name: "OSV", URL: "https://osv.dev/vulnerability/" + url.PathEscape(a)},
		})
	}
	for _, s := range d.Severity {
		if m := cvssMethod(s.Type, s.Score); m != "" {
			v.Ratings = append(v.Ratings, BOMRating{Method: m, Vector: s.Score})
		}
	}
	if sev := severityWord(d.DatabaseSpecific.Severity); sev != "" {
		v.Ratings = append(v.Ratings, BOMRating{Severity: sev, Method: "other"})
	}
	return v
}

// cvssMethod names a CVSS vector the way CycloneDX's enumeration does.
func cvssMethod(kind, vector string) string {
	switch kind {
	case "CVSS_V2":
		return "CVSSv2"
	case "CVSS_V3":
		if strings.HasPrefix(vector, "CVSS:3.1/") {
			return "CVSSv31"
		}
		return "CVSSv3"
	case "CVSS_V4":
		return "CVSSv4"
	}
	return ""
}

// severityWord maps a database's own severity onto CycloneDX's words.
// GitHub says MODERATE where CycloneDX says medium.
func severityWord(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "moderate", "medium":
		return "medium"
	case "low":
		return "low"
	}
	return ""
}

// osvDo makes one request and decodes a bounded answer.
func osvDo(ctx context.Context, client *http.Client, method, target string, body []byte, into any) error {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return fmt.Errorf("supply: OSV: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("supply: OSV: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, osvMaxBody+1))
	if err != nil {
		return fmt.Errorf("supply: OSV: %w", err)
	}
	if len(data) > osvMaxBody {
		return fmt.Errorf("supply: OSV answer to %s is larger than %d MiB", target, osvMaxBody>>20)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("supply: OSV answered %s with %s", target, resp.Status)
	}
	if err := json.Unmarshal(data, into); err != nil {
		return fmt.Errorf("supply: OSV answer to %s is not the expected JSON: %w", target, err)
	}
	return nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// truncateText bounds untrusted text on a rune boundary.
func truncateText(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= n {
		return string(r)
	}
	return string(r[:n-1]) + "…"
}
