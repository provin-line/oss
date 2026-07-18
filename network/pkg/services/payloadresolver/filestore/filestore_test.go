package filestore_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/payloadresolver/filestore"
)

// tempFileNames returns the base names of every file directly under dir whose
// name starts with the ".tmp-" prefix filestore uses for in-flight writes.
func tempFileNames(t *testing.T, dir string) []string {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var names []string
	for _, de := range des {
		if strings.HasPrefix(de.Name(), ".tmp-") {
			names = append(names, de.Name())
		}
	}
	return names
}

// TestStoreWriter_Abort_NoFileLeftBehind pins that Abort removes the temp file
// from disk entirely — an aborted streaming retain leaves no trace in the
// store directory.
func TestStoreWriter_Abort_NoFileLeftBehind(t *testing.T) {
	dir := t.TempDir()
	store, err := filestore.NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	w, err := store.StoreWriter(context.Background(), "did:dplaax:reg:org:acme:pipeline:pipe-a")
	if err != nil {
		t.Fatalf("StoreWriter: %v", err)
	}
	if _, err := w.Write([]byte("bytes that must never touch disk after abort")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(des) != 0 {
		var names []string
		for _, de := range des {
			names = append(names, de.Name())
		}
		t.Errorf("store dir after Abort = %v, want empty", names)
	}
}

// TestStoreWriter_UnclosedWriter_SweptByFreshConstructor pins the crash
// recovery contract: a writer that is neither Committed nor Aborted (the
// process crashed mid-stream) leaves only its temp file on disk, and a FRESH
// store constructor pointed at the same directory sweeps it — no orphaned
// temp survives a restart.
func TestStoreWriter_UnclosedWriter_SweptByFreshConstructor(t *testing.T) {
	dir := t.TempDir()
	store, err := filestore.NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	w, err := store.StoreWriter(context.Background(), "did:dplaax:reg:org:acme:pipeline:pipe-a")
	if err != nil {
		t.Fatalf("StoreWriter: %v", err)
	}
	if _, err := w.Write([]byte("bytes orphaned by a simulated crash")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Simulate a crash: neither Commit nor Abort is called. Only the temp file
	// should be on disk at this point.
	if names := tempFileNames(t, dir); len(names) != 1 {
		t.Fatalf("temp files before restart = %v, want exactly 1", names)
	}

	// A fresh store constructor (simulating process restart) must sweep it.
	if _, err := filestore.NewStore(dir); err != nil {
		t.Fatalf("NewStore (restart): %v", err)
	}
	if names := tempFileNames(t, dir); len(names) != 0 {
		t.Errorf("temp files after restart sweep = %v, want none", names)
	}
}

// TestStoreWriter_Commit_LeavesNoTempFile pins that a successful Commit
// renames the temp file to its content-addressed final name — no ".tmp-"
// residue survives a commit.
func TestStoreWriter_Commit_LeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	store, err := filestore.NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	w, err := store.StoreWriter(context.Background(), "did:dplaax:reg:org:acme:pipeline:pipe-a")
	if err != nil {
		t.Fatalf("StoreWriter: %v", err)
	}
	payload := []byte("committed bytes")
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	hash, err := w.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if names := tempFileNames(t, dir); len(names) != 0 {
		t.Errorf("temp files after Commit = %v, want none", names)
	}
	hexPart := strings.TrimPrefix(hash, "sha256:")
	if _, err := os.Stat(filepath.Join(dir, hexPart+".bin")); err != nil {
		t.Errorf("committed bin file missing: %v", err)
	}
}
