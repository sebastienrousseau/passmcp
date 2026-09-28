// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"satellion.com/passmcp/internal/supply"
)

// The test binary is itself a Go binary built by the toolchain under test,
// which makes it the honest fixture for this: a real module graph, with
// real checksums, that nobody wrote by hand.
func selfPath(t *testing.T) string {
	t.Helper()
	p, err := os.Executable()
	if err != nil {
		t.Skipf("cannot find the test binary: %v", err)
	}
	return p
}

var (
	builtOnce sync.Once
	builtPath string
	builtErr  error
)

// withModuleGraph returns a binary that records its dependencies. The test
// binary does on Go 1.27, and on Go 1.26 — go.mod's floor, which CI gates
// on — it records none, so a test reading it would be judging the toolchain
// rather than the command. There the real passmcp binary is built instead.
func withModuleGraph(t *testing.T) string {
	t.Helper()
	self := selfPath(t)
	if bi, err := buildinfo.ReadFile(self); err == nil && len(bi.Deps) > 0 {
		return self
	}
	builtOnce.Do(func() {
		dir, err := os.MkdirTemp("", "passmcp-sbom-*")
		if err != nil {
			builtErr = err
			return
		}
		builtPath = filepath.Join(dir, "passmcp")
		if runtime.GOOS == "windows" {
			builtPath += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", builtPath, "../cmd/passmcp") //nolint:gosec // the toolchain running this test, on this module
		if out, err := cmd.CombinedOutput(); err != nil {
			builtErr = errors.New(string(out))
		}
	})
	if builtErr != nil {
		t.Skipf("the test binary records no module graph and building passmcp failed: %v", builtErr)
	}
	return builtPath
}

// TestSBOMEmitsADocumentAScannerCanRead.
func TestSBOMEmitsADocumentAScannerCanRead(t *testing.T) {
	out, code := run(t, "sbom", withModuleGraph(t))
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	var doc struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Serial      string `json:"serialNumber"`
		Metadata    struct {
			Tools []struct{ Name, Version string } `json:"tools"`
		} `json:"metadata"`
		Components []struct {
			Name, PURL string
			Hashes     []struct{ Alg, Content string }
		} `json:"components"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("what was written is not JSON: %v\n%s", err, out)
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.6" {
		t.Errorf("format = %q %q", doc.BOMFormat, doc.SpecVersion)
	}
	if !strings.HasPrefix(doc.Serial, "urn:uuid:") {
		t.Errorf("serialNumber = %q", doc.Serial)
	}
	if len(doc.Metadata.Tools) != 1 || doc.Metadata.Tools[0].Version != Version {
		t.Errorf("the document does not carry passmcp's version: %+v", doc.Metadata.Tools)
	}
	// This binary links cobra, so a graph with nothing in it means the
	// command wrote a document about nothing and exited zero.
	if len(doc.Components) == 0 {
		t.Fatal("no components, from a binary that has dependencies")
	}
	var withHash int
	for _, c := range doc.Components {
		if c.PURL == "" || !strings.HasPrefix(c.PURL, "pkg:golang/") {
			t.Errorf("component %q has no usable purl: %q", c.Name, c.PURL)
		}
		if len(c.Hashes) > 0 {
			withHash++
		}
	}
	if withHash == 0 {
		t.Error("not one dependency carried a checksum, so the document cannot be verified")
	}
}

// TestSBOMRefusesSomethingThatIsNotAGoBinary. The failure mode this guards
// against is a pipeline that ingests an empty document and goes green: for
// a Python server there is nothing to read, and saying so beats writing a
// bill of materials with no materials in it.
func TestSBOMRefusesSomethingThatIsNotAGoBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		// LookPath resolves by extension there, so a script with no
		// recognised suffix is not executable and the error is a
		// different one.
		t.Skip("PATH resolution on Windows keys on the extension")
	}
	p := filepath.Join(t.TempDir(), "server.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { // #nosec G306 -- it must be executable
		t.Fatal(err)
	}

	out, code := run(t, "sbom", p)
	if code == 0 {
		t.Fatalf("a shell script produced a bill of materials:\n%s", out)
	}
	if out != "" {
		t.Errorf("something was written to stdout for a program it could not read:\n%s", out)
	}

	// The exit code alone does not say which failure this was, and the
	// final message goes to the process's own stderr rather than through
	// anything the harness captures. Asked of the command directly, so the
	// reason is the one under test and not "could not open the file".
	err := sbomCmd.RunE(sbomCmd, []string{p})
	if err == nil {
		t.Fatal("no error from a program that is not a Go binary")
	}
	if !errors.Is(err, supply.ErrNotGo) {
		t.Errorf("the reason is not the one being tested: %v", err)
	}
	if !strings.Contains(err.Error(), "project directory") {
		t.Errorf("the message does not say what to do instead: %v", err)
	}
}

// TestSBOMReadsAProjectDirectory. The routing is what is under test here;
// the lockfile formats are tested in internal/supply.
func TestSBOMReadsAProjectDirectory(t *testing.T) {
	dir := t.TempDir()
	lock := "httpx==0.27.2 --hash=sha256:44c3f6f83c39094fec0db8b7f158d0a8fad3418e77f5f739b103e1ac73eee5d8\nstarlette>=0.38\n"
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := run(t, "sbom", dir)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	var doc struct {
		BOMFormat string `json:"bomFormat"`
		Metadata  struct {
			Properties []struct{ Name, Value string } `json:"properties"`
		} `json:"metadata"`
		Components []struct {
			PURL       string `json:"purl"`
			Properties []struct{ Name, Value string }
		} `json:"components"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if doc.BOMFormat != "CycloneDX" || len(doc.Components) != 2 {
		t.Fatalf("document = %+v", doc)
	}
	if doc.Components[0].PURL != "pkg:pypi/httpx@0.27.2" {
		t.Errorf("first component = %q", doc.Components[0].PURL)
	}
	if len(doc.Components[1].Properties) == 0 || doc.Components[1].Properties[0].Name != "passmcp:unverifiable" {
		t.Errorf("an unpinned requirement is not marked: %+v", doc.Components[1])
	}
	var evidence bool
	for _, p := range doc.Metadata.Properties {
		evidence = evidence || p.Name == "passmcp:evidence"
	}
	if !evidence {
		t.Error("the document does not say it was read from a lockfile")
	}
}

// TestSBOMOnADirectoryWithNoLockfile fails rather than writing an empty
// inventory, for the same reason a non-Go binary does.
func TestSBOMOnADirectoryWithNoLockfile(t *testing.T) {
	dir := t.TempDir()
	out, code := run(t, "sbom", dir)
	if code == 0 || out != "" {
		t.Fatalf("exit %d, stdout:\n%s", code, out)
	}
	if err := sbomCmd.RunE(sbomCmd, []string{dir}); !errors.Is(err, supply.ErrNoManifest) {
		t.Errorf("err = %v, want ErrNoManifest", err)
	}
}

// TestSBOMReportsAMissingProgram rather than writing an empty document.
func TestSBOMReportsAMissingProgram(t *testing.T) {
	out, code := run(t, "sbom", filepath.Join(t.TempDir(), "absent"))
	if code == 0 {
		t.Fatalf("a program that does not exist produced a document:\n%s", out)
	}
}

// TestSBOMNeedsExactlyOneProgram: a bare `passmcp sbom` that read something
// from the environment would be a surprise in a pipeline.
func TestSBOMNeedsExactlyOneProgram(t *testing.T) {
	if _, code := run(t, "sbom"); code == 0 {
		t.Error("a bare sbom command succeeded")
	}
}

// TestBuildTimestampHonoursSourceDateEpoch. The serial is already derived
// from what is described, so the clock is the only field left that would
// make two descriptions of one binary differ.
func TestBuildTimestampHonoursSourceDateEpoch(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	if got := buildTimestamp(); !got.Equal(time.Unix(1700000000, 0).UTC()) {
		t.Errorf("buildTimestamp = %s, want the epoch it was given", got)
	}

	// A malformed value is somebody asking for reproducibility and getting
	// it wrong. Falling back is right; doing so silently is not, and the
	// note goes to stderr because stdout carries the document.
	t.Setenv("SOURCE_DATE_EPOCH", "the ides of march")
	before := time.Now().Add(-time.Minute)
	if got := buildTimestamp(); got.Before(before) {
		t.Errorf("a malformed epoch was used anyway: %s", got)
	}

	t.Setenv("SOURCE_DATE_EPOCH", "")
	if got := buildTimestamp(); got.Before(before) {
		t.Errorf("with nothing set, buildTimestamp = %s", got)
	}
}

// TestSBOMIsReproducible end to end, which is the claim the help text
// makes and the one a pipeline diffing two documents depends on.
func TestSBOMIsReproducible(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	self := selfPath(t)

	first, code := run(t, "sbom", self)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, first)
	}
	second, _ := run(t, "sbom", self)
	if first != second {
		t.Error("the same binary described twice gave different bytes")
	}
}

// fakeOSVServer answers every package with one advisory, and records
// what it was asked.
func fakeOSVServer(t *testing.T) (string, *[]string) {
	t.Helper()
	var sent []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/querybatch":
			var req struct {
				Queries []struct {
					Package struct{ PURL string } `json:"package"`
				} `json:"queries"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			results := make([]map[string]any, len(req.Queries))
			for i, q := range req.Queries {
				sent = append(sent, q.Package.PURL)
				results[i] = map[string]any{"vulns": []map[string]string{{"id": "GHSA-test"}}}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
		case strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			_, _ = io.WriteString(w, `{"id":"GHSA-test","summary":"a test advisory","database_specific":{"severity":"HIGH"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &sent
}

// TestSBOMWithOSVAddsAdvisoriesAndSaysWhatItSent. What leaves the machine
// is announced on stderr before it leaves, and the document on stdout
// stays pure JSON.
func TestSBOMWithOSVAddsAdvisoriesAndSaysWhatItSent(t *testing.T) {
	endpoint, sent := fakeOSVServer(t)
	dir := t.TempDir()
	lock := "httpx==0.27.2\n"
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	out, stderr, code := runCapturingStderr(t, "sbom", dir, "--osv", "--osv-url", endpoint)
	if code != 0 {
		t.Fatalf("exit %d:\n%s\n%s", code, out, stderr)
	}
	var doc struct {
		Vulnerabilities []struct {
			ID      string
			Affects []struct{ Ref string }
			Ratings []struct{ Severity string }
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout is not the document: %v\n%s", err, out)
	}
	if len(doc.Vulnerabilities) != 1 || doc.Vulnerabilities[0].Affects[0].Ref != "pkg:pypi/httpx@0.27.2" {
		t.Fatalf("vulnerabilities = %+v", doc.Vulnerabilities)
	}
	if strings.Join(*sent, ",") != "pkg:pypi/httpx@0.27.2" {
		t.Errorf("sent %v", *sent)
	}
	if !strings.Contains(stderr, "sending 1 package URLs to "+endpoint) {
		t.Errorf("the egress was not announced:\n%s", stderr)
	}
}

// TestSBOMWithoutOSVMakesNoRequest. Off by default is the guarantee.
func TestSBOMWithoutOSVMakesNoRequest(t *testing.T) {
	_, sent := fakeOSVServer(t)
	out, code := run(t, "sbom", selfPath(t))
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if len(*sent) != 0 || strings.Contains(out, "vulnerabilities") {
		t.Errorf("a document without --osv looked something up: sent %v", *sent)
	}
}

// TestSBOMOSVURLWithoutOSVIsRefused rather than silently ignored.
func TestSBOMOSVURLWithoutOSVIsRefused(t *testing.T) {
	out, code := run(t, "sbom", selfPath(t), "--osv-url", "https://mirror.example")
	if code == 0 || out != "" {
		t.Fatalf("exit %d, stdout:\n%s", code, out)
	}
}

// TestSBOMFailsWhenTheLookupFails rather than writing a document that
// reads as clean.
func TestSBOMFailsWhenTheLookupFails(t *testing.T) {
	out, code := run(t, "sbom", selfPath(t), "--osv", "--osv-url", "http://mirror.corp.example")
	if code == 0 || out != "" {
		t.Fatalf("exit %d, stdout:\n%s", code, out)
	}
}
