// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package canary

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// requirePOSIXPermissions skips a test whose subject is a Unix mode bit.
//
// Windows has no permission bits: Go reports 0666 whatever mode was asked
// for, so `perm & 0o077` is always non-zero and a chmod restricts nothing.
// A test asserting either is testing the platform rather than the code.
func requirePOSIXPermissions(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("no Unix permission bits here; Go reports 0666 whatever mode was asked for")
	}
}

func seed(t *testing.T) *Canary {
	t.Helper()
	c, err := Seed(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestSeedPlantsCredentialsWhereTheyLive. A decoy somewhere nothing looks
// tests nothing.
func TestSeedPlantsCredentialsWhereTheyLive(t *testing.T) {
	c := seed(t)
	for _, want := range []string{".ssh/id_rsa", ".aws/credentials", ".env", ".netrc"} {
		p := filepath.Join(c.Dir(), filepath.FromSlash(want))
		fi, err := os.Stat(p)
		if err != nil {
			t.Errorf("%s was not planted: %v", want, err)
			continue
		}
		if runtime.GOOS == "windows" {
			continue
		}
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s is mode %v; a credential file that is world-readable is conspicuous", want, perm)
		}
	}
}

// TestDecoysLookLikeTheRealThing: something grepping for a private key
// header has to find one, or it walks past the decoy.
func TestDecoysLookLikeTheRealThing(t *testing.T) {
	c := seed(t)
	for name, want := range map[string]string{
		".ssh/id_rsa":      "BEGIN OPENSSH PRIVATE KEY",
		".aws/credentials": "aws_secret_access_key",
		".env":             "DATABASE_URL",
		".netrc":           "password",
	} {
		b, err := os.ReadFile(filepath.Join(c.Dir(), filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), want) {
			t.Errorf("%s does not look like a real one: %q", name, b)
		}
	}
}

// TestMarkersAreUniquePerFileAndPerRun. A marker shared between two files
// could not say which one leaked; one shared between two runs could not
// say which run.
func TestMarkersAreUniquePerFileAndPerRun(t *testing.T) {
	a := seed(t)
	b := seed(t)

	seen := map[string]bool{}
	for _, m := range append(a.Markers(), b.Markers()...) {
		if seen[m] {
			t.Errorf("marker %q was reused", m)
		}
		seen[m] = true
		if !strings.HasPrefix(m, "passmcp-canary-") {
			t.Errorf("marker %q is not traceable back to passmcp", m)
		}
	}
	if len(seen) != len(a.Markers())+len(b.Markers()) {
		t.Error("markers collided across runs")
	}
}

// TestMarkersAreInTheFiles, which is what makes a marker leaving proof
// that the file was read.
func TestMarkersAreInTheFiles(t *testing.T) {
	c := seed(t)
	for _, m := range c.Markers() {
		name := c.MarkerName(m)
		if name == "" {
			t.Fatalf("marker %q maps to no file", m)
		}
		b, err := os.ReadFile(filepath.Join(c.Dir(), filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), m) {
			t.Errorf("%s does not contain its own marker", name)
		}
	}
	if c.MarkerName("passmcp-canary-nothing") != "" {
		t.Error("an unknown marker resolved to a file")
	}
}

// TestFindMarkersReportsTheFileNotTheMarker: a report names the file,
// because the marker is evidence rather than a message.
func TestFindMarkersReportsTheFileNotTheMarker(t *testing.T) {
	c := seed(t)
	m := c.Markers()[0]
	got := c.FindMarkers("some outbound body with " + m + " buried in it")
	if len(got) != 1 || got[0] != c.MarkerName(m) {
		t.Fatalf("FindMarkers = %v, want [%s]", got, c.MarkerName(m))
	}
	if len(c.FindMarkers("nothing to see")) != 0 {
		t.Error("a clean body reported a marker")
	}
	if len(c.FindMarkers("")) != 0 {
		t.Error("an empty body reported a marker")
	}
}

// TestEnvPointsHomeAtTheDecoys, in both spellings, since a good number of
// libraries consult USERPROFILE first.
func TestEnvPointsHomeAtTheDecoys(t *testing.T) {
	c := seed(t)
	env := strings.Join(c.Env(), "\n")
	for _, name := range []string{"HOME=", "USERPROFILE="} {
		if !strings.Contains(env, name+c.Dir()) {
			t.Errorf("%s does not point at the scratch home:\n%s", name, env)
		}
	}
}

// TestAtimeInstrumentReportsItself is the property the whole design rests
// on: whatever the answer, the canary knows whether it can answer.
func TestAtimeInstrumentReportsItself(t *testing.T) {
	c := seed(t)
	usable, why := c.AtimeUsable()
	if usable && why != "" {
		t.Errorf("a working instrument should not also explain itself: %q", why)
	}
	if !usable && why == "" {
		t.Error("an unusable instrument must say why")
	}
	// And the readings must be empty rather than misleading when it does
	// not work, which is what stops a caller reading "none" as "clean".
	if !usable && len(c.Opened()) != 0 {
		t.Error("an unusable instrument reported readings")
	}
}

// TestOpenedNoticesARead, where the filesystem records one at all.
func TestOpenedNoticesARead(t *testing.T) {
	c := seed(t)
	if usable, why := c.AtimeUsable(); !usable {
		t.Skipf("this filesystem cannot record the witness: %s", why)
	}

	target := filepath.Join(c.Dir(), filepath.FromSlash(".ssh/id_rsa"))
	if _, err := os.ReadFile(target); err != nil { //nolint:gosec // reading the decoy is the test
		t.Fatal(err)
	}

	opened := c.Opened()
	if len(opened) != 1 || opened[0].Name != ".ssh/id_rsa" {
		t.Fatalf("Opened = %+v, want just .ssh/id_rsa", opened)
	}
	if !opened[0].Read {
		t.Error("the decoy was not marked as read")
	}
}

// TestCloseRemovesEverything: passmcp must not leave a directory of
// plausible-looking credentials on somebody's machine.
func TestCloseRemovesEverything(t *testing.T) {
	c, err := Seed(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := c.Dir()
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("the scratch home survived Close: %v", err)
	}
	// And a second close is harmless, because it runs on a defer.
	if err := c.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// TestSeedFailsOnAnUnusableRoot, rather than planting nothing and
// reporting success.
func TestSeedFailsOnAnUnusableRoot(t *testing.T) {
	if _, err := Seed(filepath.Join(t.TempDir(), "does", "not", "exist")); err == nil {
		t.Error("seeding into a missing directory should fail")
	}
}

// TestAccessTimeOnAMissingFile reports that it cannot tell, rather than a
// zero time a caller might compare against.
func TestAccessTimeOnAMissingFile(t *testing.T) {
	if _, ok := accessTime(filepath.Join(t.TempDir(), "absent")); ok {
		t.Error("a missing file reported an access time")
	}
}

// TestOpenedIsEmptyOnAnUnreadableDecoy: a decoy that has gone is not a
// decoy that was read, and must not be reported as one.
func TestOpenedIsEmptyOnAnUnreadableDecoy(t *testing.T) {
	c := seed(t)
	if usable, why := c.AtimeUsable(); !usable {
		t.Skipf("this filesystem cannot record the witness: %s", why)
	}
	// Remove every decoy; nothing can have been read.
	for _, name := range []string{".ssh/id_rsa", ".aws/credentials", ".env", ".netrc"} {
		_ = os.Remove(filepath.Join(c.Dir(), filepath.FromSlash(name)))
	}
	if opened := c.Opened(); len(opened) != 0 {
		t.Errorf("Opened = %+v, want none", opened)
	}
}

// TestCloseOnAZeroCanaryIsHarmless, since callers defer it.
func TestCloseOnAZeroCanaryIsHarmless(t *testing.T) {
	var c Canary
	if err := c.Close(); err != nil {
		t.Errorf("Close on a zero canary: %v", err)
	}
}

// TestMeasureAtimeOnAnUnwritableDirectory reports why rather than
// claiming the instrument works.
func TestMeasureAtimeOnAnUnwritableDirectory(t *testing.T) {
	ok, why := measureAtime(filepath.Join(t.TempDir(), "nope"))
	if ok {
		t.Error("measuring in a missing directory reported success")
	}
	if why == "" {
		t.Error("a failed measurement must say why")
	}
}

// TestSeedBackdatesTheDecoys, which is what lets a filesystem using
// relatime notice the first read at all.
func TestSeedBackdatesTheDecoys(t *testing.T) {
	c := seed(t)
	for _, name := range []string{".ssh/id_rsa", ".env"} {
		fi, err := os.Stat(filepath.Join(c.Dir(), filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if age := time.Since(fi.ModTime()); age < 24*time.Hour {
			t.Errorf("%s is only %v old; relatime would not record a read", name, age)
		}
	}
}

// TestOpenedLogicWhereAccessTimesAreReadable covers the reading itself on
// a machine whose filesystem records no access at all.
//
// White-box on purpose. TestOpenedNoticesARead is the real thing and runs
// only where access times actually move; this drives the same code by
// claiming the instrument works and backdating what it compares against,
// so the walk, the comparison and the ordering are exercised on macOS as
// well as Linux rather than only where the question can be answered.
//
// It still needs a platform that reports an access time at all. Windows
// does not -- accessTime there returns "cannot tell" by construction, so
// Opened finds nothing and there is no logic left to exercise. An earlier
// name for this test said "everywhere", which was wrong in exactly the
// way the test then failed.
func TestOpenedLogicWhereAccessTimesAreReadable(t *testing.T) {
	c := seed(t)
	if _, ok := accessTime(c.decoys[0].Path); !ok {
		t.Skip("this platform does not report access times at all; there is nothing to exercise")
	}
	c.atimeOK = true

	// Every decoy's baseline moved to the distant past, so whatever the
	// filesystem currently reports counts as later.
	for _, d := range c.decoys {
		d.seeded = time.Unix(0, 0)
	}

	opened := c.Opened()
	if len(opened) != len(c.decoys) {
		t.Fatalf("Opened reported %d of %d decoys", len(opened), len(c.decoys))
	}
	if !sortedByName(opened) {
		t.Errorf("Opened is not ordered by name: %+v", opened)
	}
	for _, d := range opened {
		if !d.Read {
			t.Errorf("%s was returned but not marked read", d.Name)
		}
	}

	// And with the instrument declared unusable, the same state reports
	// nothing at all — which is the property that stops a caller reading
	// "none" as "clean".
	c.atimeOK = false
	if got := c.Opened(); got != nil {
		t.Errorf("an unusable instrument reported %+v", got)
	}
}

func sortedByName(ds []Decoy) bool {
	for i := 1; i < len(ds); i++ {
		if ds[i-1].Name > ds[i].Name {
			return false
		}
	}
	return true
}

// TestPlantFailsOnADirectoryItCannotWriteTo. Planting three of four
// decoys and reporting success would mean a run that watched less than it
// said it did.
func TestPlantFailsOnADirectoryItCannotWriteTo(t *testing.T) {
	requirePOSIXPermissions(t)
	if os.Geteuid() == 0 {
		t.Skip("running as root, where permissions are not enforced")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if _, err := plant(dir); err == nil {
		t.Error("planting into a read-only directory should fail")
	}
}
