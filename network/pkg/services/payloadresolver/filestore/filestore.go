// Package filestore is the file-backed payloadresolver.Store — the durable
// serving substrate for by-reference payload delivery.
//
// Layout (two files per entry under the store root, named by content address):
//
//	<hex>.bin    — the raw payload bytes (content-addressed, write-once;
//	               overwriting is harmless — the same hash carries the same bytes)
//	<hex>.owners — {"v":1,"owners":[...]} the emitter pipeline DID set
//
// The bin file is the authoritative bytes; the owners sidecar is the
// authorization basis for serving. Get recomputes sha256(bin) and compares it
// to the key: a tampered-but-present file is a damaged entry, never served.
//
// Damage/crash posture: the bytes are immutable evidence — a Get that reads an
// unreadable or tampered bin is an error, never ErrNotFound. The owner set is
// read-modify-write working state guarded by a per-store mutex; bin is written
// before owners, so a crash between them leaves present bytes with an
// incomplete (possibly empty) owner set — which fails CLOSED at the serving
// boundary (no owner admits) and is repaired by the next retain of the same
// payload.
package filestore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver"
	"github.com/provin-line/oss/vc"
)

// Store is the file-backed payloadresolver.Store.
type Store struct {
	mu  sync.RWMutex
	dir string
}

var _ payloadresolver.Store = (*Store)(nil)

// ownersEnvelope is the on-disk shape of an entry's owner set: a versioned
// envelope so a later format change can migrate instead of guessing.
type ownersEnvelope struct {
	V      int      `json:"v"`
	Owners []string `json:"owners"`
}

// NewStore opens (creating if needed) the payload store rooted at dir. An
// uncreatable or unwritable root is an error — a node that cannot persist the
// payloads it agreed to serve must not pretend to (boot fails closed).
//
// It also sweeps orphaned ".tmp-" files left behind by a crash — including a
// StoreWriter whose Commit/Abort never ran (e.g. the process died mid-stream)
// — so a restart never accumulates unreachable temp files.
func NewStore(dir string) (*Store, error) {
	if err := openDir(dir); err != nil {
		return nil, fmt.Errorf("filestore: open payload store %s: %w", dir, err)
	}
	return &Store{dir: dir}, nil
}

func hashPayload(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// paths returns the bin and owners file paths for a validated content address.
func (s *Store) paths(hash string) (binPath, ownersPath string, err error) {
	if !vc.IsContentAddress(hash) {
		return "", "", fmt.Errorf("%w: %q is not a sha256:<hex> content address", payloadresolver.ErrInvalidArgument, hash)
	}
	hexPart := strings.TrimPrefix(hash, "sha256:")
	return filepath.Join(s.dir, hexPart+".bin"), filepath.Join(s.dir, hexPart+".owners"), nil
}

// Put writes the payload bytes (content-addressed, write-once) then appends
// ownerDID to the owner sidecar. A repeat owner is a no-op; the bytes are
// idempotent.
//
// Put is a thin wrapper over StoreWriter: the whole payload is written to the
// streaming writer in one call and immediately committed, so there is exactly
// ONE code path for hashing and owner-sidecar bookkeeping between the
// whole-buffer and streaming retain APIs.
func (s *Store) Put(payload []byte, ownerDID string) (string, error) {
	w, err := s.StoreWriter(context.Background(), ownerDID)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(payload); err != nil {
		_ = w.Abort()
		return "", err
	}
	return w.Commit()
}

// StoreWriter returns a streaming retain handle: it opens a temp file in the
// store directory (swept by NewStore if left behind by a crash) and hashes
// bytes incrementally as they are written, so Commit derives the SAME content
// address Put would derive for the same bytes without ever buffering the
// whole payload in memory.
func (s *Store) StoreWriter(ctx context.Context, ownerDID string) (payloadresolver.PayloadWriter, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(s.dir, ".tmp-*")
	if err != nil {
		return nil, fmt.Errorf("filestore: create temp payload file: %w", err)
	}
	return &fileWriter{
		store:    s,
		ownerDID: ownerDID,
		tmp:      tmp,
		tmpPath:  tmp.Name(),
		hasher:   sha256.New(),
	}, nil
}

// fileWriter is the filestore PayloadWriter: a temp file plus an incremental
// SHA-256 hasher fed the same bytes as they are written to disk.
type fileWriter struct {
	store    *Store
	ownerDID string
	tmp      *os.File
	tmpPath  string
	hasher   hash.Hash
	done     bool
}

// Write appends p to the temp file and feeds it to the incremental hasher.
func (w *fileWriter) Write(p []byte) (int, error) {
	if w.done {
		return 0, payloadresolver.ErrWriterFinalized
	}
	n, err := w.tmp.Write(p)
	if n > 0 {
		w.hasher.Write(p[:n])
	}
	return n, err
}

// Commit derives the content address from the bytes written so far, fsyncs
// and atomically renames the temp file to its content-addressed final name,
// then appends ownerDID to the owner sidecar — the same bookkeeping Put
// performs, applied to a file already on disk instead of an in-memory slice.
func (w *fileWriter) Commit() (string, error) {
	if w.done {
		return "", payloadresolver.ErrWriterFinalized
	}
	w.done = true
	sum := w.hasher.Sum(nil)
	contentAddr := "sha256:" + hex.EncodeToString(sum)

	if err := w.tmp.Sync(); err != nil {
		w.tmp.Close()
		os.Remove(w.tmpPath)
		return "", fmt.Errorf("filestore: sync payload %s: %w", contentAddr, err)
	}
	if err := w.tmp.Close(); err != nil {
		os.Remove(w.tmpPath)
		return "", fmt.Errorf("filestore: close payload %s: %w", contentAddr, err)
	}

	binPath, ownersPath, err := w.store.paths(contentAddr)
	if err != nil {
		os.Remove(w.tmpPath)
		return "", err
	}

	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	// Content-addressed and immutable, so renaming over an existing bin (two
	// concurrent retains of the same bytes) is harmless.
	if err := os.Rename(w.tmpPath, binPath); err != nil {
		os.Remove(w.tmpPath)
		return "", fmt.Errorf("filestore: rename payload %s: %w", contentAddr, err)
	}
	if err := fsyncDir(w.store.dir); err != nil {
		return "", fmt.Errorf("filestore: fsync payload dir: %w", err)
	}

	owners, err := readOwners(ownersPath)
	if err != nil {
		return "", fmt.Errorf("filestore: read owners %s: %w", contentAddr, err)
	}
	for _, o := range owners {
		if o == w.ownerDID {
			return contentAddr, nil // already an owner
		}
	}
	owners = append(owners, w.ownerDID)
	// The content address is sha256 of the payload bytes, never of this sidecar,
	// so the owner-set bytes are not a signing scope (canonicalizer-hygiene-exempt).
	raw, err := json.Marshal(ownersEnvelope{V: 1, Owners: owners})
	if err != nil {
		return "", fmt.Errorf("filestore: marshal owners %s: %w", contentAddr, err)
	}
	if err := writeAtomic(ownersPath, raw); err != nil {
		return "", fmt.Errorf("filestore: write owners %s: %w", contentAddr, err)
	}
	return contentAddr, nil
}

// Abort discards the temp file: nothing written to it is persisted.
func (w *fileWriter) Abort() error {
	if w.done {
		return payloadresolver.ErrWriterFinalized
	}
	w.done = true
	w.tmp.Close()
	return os.Remove(w.tmpPath)
}

// Owners returns the owner set at hash WITHOUT reading (or hashing) the payload
// bytes — the cheap authorization basis the serving boundary consults before it
// commits to reading. Existence is a stat of the bin file (no byte read, no
// alloc, no re-hash); a present entry with an absent/unreadable owner sidecar
// returns an empty set (fail-closed at serving), a definitive miss is ErrNotFound.
func (s *Store) Owners(hash string) ([]string, error) {
	binPath, ownersPath, err := s.paths(hash)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, err := os.Stat(binPath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Distinguish a definitive miss from a vanished STORE (matches Get).
			if _, statErr := os.Stat(s.dir); statErr != nil {
				return nil, fmt.Errorf("filestore: payload store root %s unavailable: %w", s.dir, statErr)
			}
			return nil, payloadresolver.ErrNotFound
		}
		return nil, fmt.Errorf("filestore: stat payload %s: %w", hash, err)
	}
	owners, err := readOwners(ownersPath)
	if err != nil {
		return nil, fmt.Errorf("filestore: read owners %s: %w", hash, err)
	}
	return owners, nil
}

// Get returns the payload bytes and owner set at hash, payloadresolver.ErrNotFound
// when the bytes are absent, or a distinct error for a damaged entry (bytes that
// no longer hash to the key).
func (s *Store) Get(hash string) ([]byte, []string, error) {
	binPath, ownersPath, err := s.paths(hash)
	if err != nil {
		return nil, nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	payload, err := os.ReadFile(binPath)
	if errors.Is(err, fs.ErrNotExist) {
		// Distinguish a definitive miss from a vanished STORE: a deleted or
		// unmounted root must not read as "payload absent".
		if _, statErr := os.Stat(s.dir); statErr != nil {
			return nil, nil, fmt.Errorf("filestore: payload store root %s unavailable: %w", s.dir, statErr)
		}
		return nil, nil, payloadresolver.ErrNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("filestore: read payload %s: %w", hash, err)
	}
	if got := hashPayload(payload); got != hash {
		return nil, nil, fmt.Errorf("filestore: damaged payload entry %s: stored bytes hash to %s (tampered or misfiled)", hash, got)
	}
	owners, err := readOwners(ownersPath)
	if err != nil {
		return nil, nil, fmt.Errorf("filestore: read owners %s: %w", hash, err)
	}
	return payload, owners, nil
}

// readOwners reads the owner sidecar, returning an empty set when it is absent
// (a bin-present/owners-absent crash residual — fail-closed at serving).
func readOwners(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var env ownersEnvelope
	// The sidecar is local working state, but decode it through the same strict
	// path as every protocol JSON: a duplicate key or trailing garbage means a
	// corrupted sidecar, which must fail closed (an empty owner set at serving),
	// never silently pick one reading.
	if err := canon.NewStrictDecoder(raw).Decode(&env); err != nil {
		return nil, fmt.Errorf("damaged owners sidecar: %w", err)
	}
	if env.V != 1 {
		return nil, fmt.Errorf("unsupported owners envelope version %d", env.V)
	}
	return env.Owners, nil
}

// writeAtomic writes data to path via temp + fsync + rename (crash-safe: a
// reader observes the old entry or the new one, never a torn one), then fsyncs
// the directory so the rename survives power loss.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return fsyncDir(filepath.Dir(path))
}

func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// openDir creates dir if needed, PROVES it is writable (MkdirAll succeeds on an
// existing read-only dir — the boot must fail closed, not the first Put), and
// sweeps orphaned temp files from interrupted writes.
func openDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	probe, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return fmt.Errorf("not writable: %w", err)
	}
	probe.Close()
	os.Remove(probe.Name())
	des, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, de := range des {
		if strings.HasPrefix(de.Name(), ".tmp-") {
			os.Remove(filepath.Join(dir, de.Name()))
		}
	}
	return nil
}
