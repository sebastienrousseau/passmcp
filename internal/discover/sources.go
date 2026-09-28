// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package discover

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
)

// The source types a target can come from.
const (
	SourceTargets  = "targets"
	SourceConfig   = "config"
	SourceGateway  = "gateway"
	SourceRegistry = "registry"
)

// ParseTargets reads a targets file: one hostname, host:port or URL per
// line, with blank lines and # comments ignored. A bare name is https.
func ParseTargets(r io.Reader, ref string) ([]Target, error) {
	var out []Target
	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		s := strings.TrimSpace(sc.Text())
		if i := strings.Index(s, "#"); i >= 0 {
			s = strings.TrimSpace(s[:i])
		}
		if s == "" {
			continue
		}
		u, err := normalise(s)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", ref, line, err)
		}
		out = append(out, Target{URL: u, Source: Source{Type: SourceTargets, Ref: ref}})
	}
	return out, sc.Err()
}

// normalise turns a line into an absolute http(s) URL.
func normalise(s string) (string, error) {
	if _, _, err := net.ParseCIDR(s); err == nil {
		// 10.0.0.0/24 would otherwise parse as a host with a path.
		return "", fmt.Errorf("%q is a range; discovery probes named hosts only", s)
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("%q is not an http or https target", s)
	}
	if u.Host == "" {
		return "", fmt.Errorf("%q names no host", s)
	}
	if strings.ContainsAny(u.Host, "*/") {
		// A range or a wildcard is a scan, and discovery does not scan.
		return "", fmt.Errorf("%q is not a single host; discovery probes named hosts only", s)
	}
	u.Fragment = ""
	return u.String(), nil
}

// FromClientConfig reads the remote servers an MCP client configuration
// declares: Claude Desktop and Cursor (mcpServers), VS Code (servers, or
// mcp.servers in settings) and Zed (context_servers). Servers started as
// programs are skipped: discovery finds endpoints, and a command line is
// not one. No value from the file other than the URL is kept.
func FromClientConfig(b []byte, ref string) ([]Target, error) {
	var doc map[string]any
	if err := json.Unmarshal(stripJSONC(b), &doc); err != nil {
		return nil, fmt.Errorf("%s is not a JSON client configuration: %w", ref, err)
	}
	var urls []string
	for _, key := range []string{"mcpServers", "servers", "context_servers"} {
		urls = append(urls, serverURLs(doc[key])...)
	}
	if mcp, ok := doc["mcp"].(map[string]any); ok {
		urls = append(urls, serverURLs(mcp["servers"])...)
	}
	return targetsFrom(urls, Source{Type: SourceConfig, Ref: ref}), nil
}

// serverURLs reads the url (or serverUrl) of each named server entry.
func serverURLs(v any) []string {
	servers, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	var out []string
	for _, entry := range servers {
		m, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		for _, k := range []string{"url", "serverUrl"} {
			if s, ok := m[k].(string); ok && s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// urlPattern finds absolute http(s) URLs in text.
var urlPattern = regexp.MustCompile(`https?://[^\s"'<>{}\[\],]+`)

// FromGatewayConfig reads the remote MCP backends a gateway configuration
// declares, agentgateway's YAML or Obot's catalogue JSON alike. It reads
// the file as text and takes each absolute URL, which avoids a YAML
// dependency and handles both formats the same way; a backend written as
// separate host, port and path fields must be listed as a URL to be found.
func FromGatewayConfig(b []byte, ref string) []Target {
	return targetsFrom(urlPattern.FindAllString(string(b), -1), Source{Type: SourceGateway, Ref: ref})
}

// targetsFrom normalises and de-duplicates URLs into targets.
func targetsFrom(urls []string, src Source) []Target {
	seen := map[string]bool{}
	var out []Target
	for _, raw := range urls {
		u, err := normalise(strings.TrimRight(raw, ".;"))
		if err != nil || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, Target{URL: u, Source: src})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

// stripJSONC removes // and /* */ comments and trailing commas outside
// strings, so the JSON-with-comments that VS Code and Zed write parses.
func stripJSONC(b []byte) []byte {
	var out bytes.Buffer
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case c == '"':
			i = copyString(&out, b, i)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			out.WriteByte('\n')
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			end := bytes.Index(b[i+2:], []byte("*/"))
			if end < 0 {
				i = len(b)
				continue
			}
			i += end + 3
		default:
			out.WriteByte(c)
		}
	}
	return trailingCommas.ReplaceAll(out.Bytes(), []byte("$1"))
}

// copyString copies the JSON string opening at b[start] to out, escapes
// and all, and returns the index of its closing quote (or the last byte of
// an unterminated one).
func copyString(out *bytes.Buffer, b []byte, start int) int {
	out.WriteByte(b[start])
	esc := false
	for i := start + 1; i < len(b); i++ {
		c := b[i]
		out.WriteByte(c)
		switch {
		case esc:
			esc = false
		case c == '\\':
			esc = true
		case c == '"':
			return i
		}
	}
	return len(b) - 1
}

// trailingCommas matches a comma before a closing bracket.
var trailingCommas = regexp.MustCompile(`,(\s*[}\]])`)

// ErrNamespace is returned for a registry namespace that is not a single
// organisation's.
var ErrNamespace = errors.New("discover: a registry namespace must name one organisation, like io.github.example")

// namespacePattern is a reverse-DNS namespace of at least three labels:
// io.github.<org> or com.example.<team>. Anything broader would enumerate
// other people's servers.
var namespacePattern = regexp.MustCompile(`^[a-z0-9-]+(\.[a-zA-Z0-9-]+){2,}$`)

// FromRegistry reads the remote endpoints listed under one namespace of an
// MCP registry, following the registry's cursor pagination. Only servers
// whose name starts with "<namespace>/" are kept: the registry's search is
// a substring match and would otherwise return other publishers' servers.
func FromRegistry(ctx context.Context, client *http.Client, base, namespace string) ([]Target, error) {
	if !namespacePattern.MatchString(namespace) {
		return nil, ErrNamespace
	}
	prefix := namespace + "/"
	var urls []string
	cursor := ""
	for page := 0; page < 50; page++ {
		body, err := registryPage(ctx, client, base, namespace, cursor)
		if err != nil {
			return nil, err
		}
		for _, s := range body.Servers {
			if strings.HasPrefix(s.Server.Name, prefix) {
				for _, r := range s.Server.Remotes {
					urls = append(urls, r.URL)
				}
			}
		}
		cursor = body.Metadata.NextCursor
		if cursor == "" {
			break
		}
	}
	return targetsFrom(urls, Source{Type: SourceRegistry, Ref: namespace}), nil
}

// registryResponse is the part of a registry list response discovery reads.
type registryResponse struct {
	Servers []struct {
		Server struct {
			Name    string `json:"name"`
			Remotes []struct {
				URL string `json:"url"`
			} `json:"remotes"`
		} `json:"server"`
	} `json:"servers"`
	Metadata struct {
		NextCursor string `json:"nextCursor"`
	} `json:"metadata"`
}

// registryPage fetches one page of a registry search.
func registryPage(ctx context.Context, client *http.Client, base, namespace, cursor string) (*registryResponse, error) {
	q := url.Values{"search": {namespace}, "limit": {"100"}}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/v0/servers?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry answered %d", resp.StatusCode)
	}
	var out registryResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("registry response: %w", err)
	}
	return &out, nil
}

// ReadFile reads a source file the operator named.
func ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path) // #nosec G304 -- the operator named the file
}
