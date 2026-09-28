// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package clientconf reads the MCP client configurations an agent host
// keeps: Claude Desktop and Cursor (`mcpServers`), VS Code (`servers` in
// .vscode/mcp.json, or `mcp.servers` in settings.json) and Zed
// (`context_servers`).
//
// A client configuration is the only place that says which servers an agent
// uses together, and how each stdio server is started. Two checks need
// exactly that: shadowing across servers, which exists only in the union of
// their catalogues, and the launch command, which is where a server's
// supply chain and its secrets are decided before it ever answers a
// request.
//
// Positions are kept. A finding about a launch command is only actionable
// with the line that carries it, and the files are JSON with comments, so
// the line cannot be recovered from the decoded value.
package clientconf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Server is one configured MCP server.
type Server struct {
	// Name is the key the configuration gives the server.
	Name string `json:"name"`
	// Command and Args start a stdio server; URL names a remote one.
	Command string   `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`
	URL     string   `json:"url,omitempty"`
	// Env and Headers hold values as sensitive as a token. They are kept for
	// the process that read the file and never cross a boundary: a spec
	// that is serialised carries only their names.
	Env     map[string]string `json:"-"`
	Headers map[string]string `json:"-"`
	// EnvNames and HeaderNames are the keys of Env and Headers, sorted.
	EnvNames    []string `json:"env_names,omitempty"`
	HeaderNames []string `json:"header_names,omitempty"`
	// Line is the 1-based line of the server's entry; CommandLine that of
	// its command, and ArgLines that of each argument, index for index.
	Line        int   `json:"line,omitempty"`
	CommandLine int   `json:"command_line,omitempty"`
	ArgLines    []int `json:"arg_lines,omitempty"`
}

// Stdio reports whether the server is a program rather than a URL.
func (s Server) Stdio() bool { return strings.TrimSpace(s.Command) != "" }

// Describe names the server's target: its URL, or its command line.
func (s Server) Describe() string {
	if s.Stdio() {
		return strings.TrimSpace(strings.Join(append([]string{s.Command}, s.Args...), " "))
	}
	return s.URL
}

// Config is one client configuration file.
type Config struct {
	// Path is the file it was read from.
	Path string `json:"path"`
	// Format names the host whose layout the file uses: claude (also Cursor
	// and Windsurf), vscode or zed.
	Format  string   `json:"format"`
	Servers []Server `json:"servers"`
}

// Secrets lists every value in the file a redactor must know before the
// first request: environment values and header values.
func (c *Config) Secrets() []string {
	if c == nil {
		return nil
	}
	var out []string
	for _, s := range c.Servers {
		for _, v := range s.Env {
			out = append(out, v)
		}
		for _, v := range s.Headers {
			out = append(out, v)
		}
	}
	return out
}

// Load reads and parses a client configuration file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the operator named the file
	if err != nil {
		return nil, err
	}
	return Parse(path, b)
}

// Parse reads a client configuration from data. path only labels it.
func Parse(path string, data []byte) (*Config, error) {
	clean := stripJSONC(data)
	var root map[string]json.RawMessage
	if err := json.Unmarshal(clean, &root); err != nil {
		return nil, fmt.Errorf("%s is not a client configuration: %w", path, err)
	}
	pos, err := positions(clean)
	if err != nil {
		return nil, fmt.Errorf("%s is not a client configuration: %w", path, err)
	}
	format, key, block := locate(root)
	if block == nil {
		return nil, fmt.Errorf("%s names no MCP servers: expected mcpServers (Claude Desktop, Cursor), servers or mcp.servers (VS Code), or context_servers (Zed)", path)
	}
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(block, &entries); err != nil {
		return nil, fmt.Errorf("%s: %s is not an object of servers: %w", path, key, err)
	}
	cfg := &Config{Path: path, Format: format}
	names := make([]string, 0, len(entries))
	for n := range entries {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		srv, err := decodeServer(n, entries[n])
		if err != nil {
			return nil, fmt.Errorf("%s: server %q: %w", path, n, err)
		}
		at := key + "." + n
		srv.Line = pos.line(at)
		srv.CommandLine = pos.line(at + commandPath(entries[n]))
		for i := range srv.Args {
			srv.ArgLines = append(srv.ArgLines, pos.line(at+argsPath(entries[n])+"["+strconv.Itoa(i)+"]"))
		}
		cfg.Servers = append(cfg.Servers, srv)
	}
	return cfg, nil
}

// locate finds the server block and says which host's layout it is.
func locate(root map[string]json.RawMessage) (format, key string, block json.RawMessage) {
	if b, ok := root["mcpServers"]; ok {
		return "claude", "mcpServers", b
	}
	if b, ok := root["context_servers"]; ok {
		return "zed", "context_servers", b
	}
	if b, ok := root["servers"]; ok {
		return "vscode", "servers", b
	}
	if raw, ok := root["mcp"]; ok {
		var mcp map[string]json.RawMessage
		if json.Unmarshal(raw, &mcp) == nil {
			if b, ok := mcp["servers"]; ok {
				return "vscode", "mcp.servers", b
			}
		}
	}
	return "", "", nil
}

// rawServer is the union of the shapes the hosts use for one entry.
type rawServer struct {
	Type      string            `json:"type"`
	Command   json.RawMessage   `json:"command"`
	Args      []string          `json:"args"`
	Env       map[string]string `json:"env"`
	URL       string            `json:"url"`
	ServerURL string            `json:"serverUrl"`
	Headers   map[string]string `json:"headers"`
}

// zedCommand is Zed's older nested command form.
type zedCommand struct {
	Path string            `json:"path"`
	Args []string          `json:"args"`
	Env  map[string]string `json:"env"`
}

func decodeServer(name string, raw json.RawMessage) (Server, error) {
	var r rawServer
	if err := json.Unmarshal(raw, &r); err != nil {
		return Server{}, err
	}
	s := Server{Name: name, Args: r.Args, Env: r.Env, Headers: r.Headers, URL: r.URL}
	if s.URL == "" {
		s.URL = r.ServerURL
	}
	if err := s.decodeCommand(r.Command); err != nil {
		return Server{}, err
	}
	// Blank is absent: a command of spaces would otherwise pass here and
	// then fail Stdio, leaving a server that is neither kind.
	if strings.TrimSpace(s.Command) == "" && strings.TrimSpace(s.URL) == "" {
		return Server{}, errors.New("has neither a command nor a url")
	}
	s.EnvNames, s.HeaderNames = keys(s.Env), keys(s.Headers)
	return s, nil
}

// decodeCommand reads a command given as a string, or in Zed's nested
// {path, args, env} form.
func (s *Server) decodeCommand(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	if json.Unmarshal(raw, &s.Command) == nil {
		return nil
	}
	var z zedCommand
	if err := json.Unmarshal(raw, &z); err != nil {
		return errors.New("command is neither a string nor {path, args, env}")
	}
	s.Command, s.Args = z.Path, z.Args
	if s.Env == nil {
		s.Env = z.Env
	}
	return nil
}

// commandPath and argsPath say where, inside an entry, the command and its
// arguments sit: at the top, or inside Zed's nested command object.
func commandPath(raw json.RawMessage) string {
	if nestedCommand(raw) {
		return ".command.path"
	}
	return ".command"
}

func argsPath(raw json.RawMessage) string {
	if nestedCommand(raw) {
		return ".command.args"
	}
	return ".args"
}

func nestedCommand(raw json.RawMessage) bool {
	var r struct {
		Command json.RawMessage `json:"command"`
	}
	_ = json.Unmarshal(raw, &r)
	return len(bytes.TrimSpace(r.Command)) > 0 && bytes.TrimSpace(r.Command)[0] == '{'
}

func keys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- positions ---------------------------------------------------------------

// positionIndex maps a dotted path (servers.name.args[2]) to the byte
// offset where its value starts, and turns offsets into lines.
type positionIndex struct {
	at   map[string]int64
	data []byte
}

func (p positionIndex) line(path string) int {
	off, ok := p.at[path]
	if !ok {
		return 0
	}
	return 1 + bytes.Count(p.data[:off], []byte("\n"))
}

// positions walks the document's tokens, recording where every value
// starts. The decoder reports the offset after each token; the start of a
// value is found by skipping the separator and whitespace that follow the
// previous token.
func positions(data []byte) (positionIndex, error) {
	idx := positionIndex{at: map[string]int64{}, data: data}
	dec := json.NewDecoder(bytes.NewReader(data))
	w := walker{dec: dec, data: data, idx: idx}
	if err := w.value(""); err != nil && !errors.Is(err, io.EOF) {
		return idx, err
	}
	return idx, nil
}

type walker struct {
	dec  *json.Decoder
	data []byte
	idx  positionIndex
}

// start is the offset of the next value: past whitespace, commas and
// colons that follow the last token read.
func (w walker) start() int64 {
	off := w.dec.InputOffset()
	for off < int64(len(w.data)) {
		switch w.data[off] {
		case ' ', '\t', '\r', '\n', ',', ':':
			off++
			continue
		}
		break
	}
	return off
}

func (w walker) value(path string) error {
	w.idx.at[path] = w.start()
	tok, err := w.dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{':
		return w.object(path)
	case '[':
		return w.array(path)
	}
	return nil
}

func (w walker) object(path string) error {
	for w.dec.More() {
		tok, err := w.dec.Token()
		if err != nil {
			return err
		}
		k, _ := tok.(string)
		child := k
		if path != "" {
			child = path + "." + k
		}
		if err := w.value(child); err != nil {
			return err
		}
	}
	_, err := w.dec.Token() // }
	return err
}

func (w walker) array(path string) error {
	for i := 0; w.dec.More(); i++ {
		if err := w.value(path + "[" + strconv.Itoa(i) + "]"); err != nil {
			return err
		}
	}
	_, err := w.dec.Token() // ]
	return err
}

// --- JSON with comments ----------------------------------------------------

// stripJSONC blanks comments and trailing commas out of JSON with comments,
// the format VS Code and Zed settings use. Everything removed becomes
// spaces, and newlines are kept, so every offset and line in the result is
// the same as in the file.
//
// Comments go first, in a pass of their own, so a trailing comma followed by
// a comment is still seen as trailing.
func stripJSONC(in []byte) []byte {
	out := append([]byte(nil), in...)
	outsideStrings(out, func(i int) int {
		switch {
		case out[i] == '/' && i+1 < len(out) && out[i+1] == '/':
			for ; i < len(out) && out[i] != '\n'; i++ {
				out[i] = ' '
			}
		case out[i] == '/' && i+1 < len(out) && out[i+1] == '*':
			i = blankBlock(out, i)
		}
		return i
	})
	outsideStrings(out, func(i int) int {
		if out[i] == ',' && closesNext(out, i+1) {
			out[i] = ' '
		}
		return i
	})
	return out
}

// outsideStrings calls visit with the index of every byte outside a JSON
// string. visit returns the index it consumed up to.
func outsideStrings(b []byte, visit func(i int) int) {
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case inStr:
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
		case c == '"':
			inStr = true
		default:
			i = visit(i)
		}
	}
}

// blankBlock blanks a /* */ comment starting at i, keeping newlines, and
// returns the index of its last byte.
func blankBlock(out []byte, i int) int {
	for ; i < len(out); i++ {
		if out[i] == '*' && i+1 < len(out) && out[i+1] == '/' {
			out[i], out[i+1] = ' ', ' '
			return i + 1
		}
		if out[i] != '\n' {
			out[i] = ' '
		}
	}
	return i
}

// closesNext reports whether the next non-space byte closes an object or an
// array, which makes a comma before it a trailing one.
func closesNext(b []byte, i int) bool {
	for ; i < len(b); i++ {
		switch b[i] {
		case ' ', '\t', '\r', '\n':
			continue
		case '}', ']':
			return true
		}
		return false
	}
	return false
}
