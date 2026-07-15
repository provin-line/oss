// Package numberinventory_test covers the migration-time scan that gates the
// stored-address canonicalization switch (ForkW-1 §2.2b-1).
package numberinventory_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/provin-line/oss/internal/numberinventory"
)

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScan_CleanStoreIsGreen(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "credentials/aa.json", `{"id":"urn:1","v":1,"s":"no unsafe numbers"}`)
	writeFile(t, dir, "dids/bb.json", `{"id":"did:dplaax:x","verificationMethod":[{"id":"#k1"}]}`)

	rep, err := numberinventory.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rep.Unsafe != 0 {
		t.Errorf("Unsafe = %d, want 0 (findings: %+v)", rep.Unsafe, rep.Findings)
	}
	if rep.Scanned != 2 {
		t.Errorf("Scanned = %d, want 2", rep.Scanned)
	}
	if !rep.Safe() {
		t.Error("Safe() = false on a clean store")
	}
}

func TestScan_DetectsUnsafeInteger(t *testing.T) {
	// The tool's reason to exist: an artifact whose canonical bytes would change
	// under the RFC 8785 switch must be found BEFORE the switch, not after it
	// makes the artifact unreadable at its own stored address.
	dir := t.TempDir()
	writeFile(t, dir, "credentials/aa.json", `{"id":"urn:1","n":9007199254740993}`)
	writeFile(t, dir, "credentials/bb.json", `{"id":"urn:2","ok":1}`)

	rep, err := numberinventory.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rep.Unsafe != 1 {
		t.Fatalf("Unsafe = %d, want 1", rep.Unsafe)
	}
	if rep.Safe() {
		t.Error("Safe() = true despite an unsafe finding")
	}
	f := rep.Findings[0]
	if filepath.Base(f.File) != "aa.json" {
		t.Errorf("finding file = %s, want aa.json", f.File)
	}
	if f.Literal != "9007199254740993" {
		t.Errorf("finding literal = %q, want the raw token", f.Literal)
	}
}

func TestScan_DetectsUnsafeIntegerInEverySpelling(t *testing.T) {
	for _, body := range []string{
		`{"n":1e30}`,
		`{"n":9007199254740993e0}`,
		`{"n":9007199254740992.0}`,
		`{"deep":{"a":[{"b":1e21}]}}`,
	} {
		dir := t.TempDir()
		writeFile(t, dir, "credentials/x.json", body)
		rep, err := numberinventory.Scan(dir)
		if err != nil {
			t.Fatalf("Scan(%s): %v", body, err)
		}
		if rep.Unsafe != 1 {
			t.Errorf("%s: Unsafe = %d, want 1", body, rep.Unsafe)
		}
	}
}

func TestScan_MissingDirIsNotAnError(t *testing.T) {
	// A store that was never created holds no artifacts. That is a real,
	// reportable result — zero scanned, zero unsafe — not a failure. Treating it
	// as an error would push an operator toward skipping the gate.
	rep, err := numberinventory.Scan(filepath.Join(t.TempDir(), "never-created"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rep.Scanned != 0 || rep.Unsafe != 0 || !rep.Safe() {
		t.Errorf("got %+v, want an empty green report", rep)
	}
}

func TestScan_UndecodableArtifactIsReported(t *testing.T) {
	// An artifact the strict decoder rejects is not evidence of safety: it is an
	// artifact whose numbers were never inspected. It must not pass silently.
	dir := t.TempDir()
	writeFile(t, dir, "credentials/bad.json", `{"a":1,"a":2}`) // duplicate key
	rep, err := numberinventory.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rep.Undecodable != 1 {
		t.Errorf("Undecodable = %d, want 1", rep.Undecodable)
	}
	if rep.Safe() {
		t.Error("Safe() = true with an uninspected artifact — coverage silently dropped")
	}
}

func TestScan_IgnoresNonJSON(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "payloads/blob.bin", "\x00\x01not json")
	writeFile(t, dir, "notes.txt", "hello")
	rep, err := numberinventory.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rep.Scanned != 0 || !rep.Safe() {
		t.Errorf("got %+v, want an empty green report (payload bytes are out of scope)", rep)
	}
}
