// Package merklelog is the proof-capable tlog.Log: an RFC 6962 Merkle tree
// (SHA-256; the scheme pinned in tlog/internal/rfc6962) over a durable
// append-only NDJSON leaf journal. It implements tlog.Log AND tlog.Prover —
// inclusion and consistency proofs without log replay — where the default
// filelog implements the hash-chain contract and is audited by replay.
//
// Durability follows filelog's discipline: the journal is the source of
// truth and the tree is a cache rebuilt at open; committed length advances
// strictly after fsync; a failed append rolls the file back to the last
// committed length, and a failed rollback poisons the log (appending after
// a partial record is never allowed); reopen truncates ONLY an unterminated
// final fragment (an uncommitted append from a crash — loudly), while a
// newline-terminated malformed line or interior corruption is refused, not
// hidden. A directory has at most one live opener (exclusive advisory
// flock, self-releasing on crash).
//
// Record.Hash is the RFC 6962 leaf hash (lowercase hex) — the tree-log form
// the tlog.Record contract names; Checkpoint.Head is the Merkle root.
package merklelog

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/tlog/internal/rfc6962"
)

// ErrLocked is returned by New when another live opener already holds the
// journal (single-opener guard).
var ErrLocked = errors.New("merklelog: log directory is locked by another opener")

const journalName = "leaves.ndjson"

// entry is the on-disk envelope: local storage bytes, never signed as-is
// (the tree commits to payloads via leaf hashes; the checkpoint signs the
// JCS view). The stored leaf hash is a replay integrity check: a rewritten
// payload no longer matches its recorded leaf and the open is refused.
type entry struct {
	V       int    `json:"v"`
	Index   uint64 `json:"index"`
	Payload []byte `json:"payload"`
	Leaf    string `json:"leaf"`
}

// Log is the file-backed Merkle tlog.Log. Construct with New; Close
// releases the file handle and the single-opener lock.
type Log struct {
	mu       sync.Mutex
	file     *os.File
	size     int64 // committed byte length — advances strictly after fsync
	payloads [][]byte
	leaves   [][rfc6962.HashSize]byte
	signer   *tlog.CheckpointSigner
	clock    func() time.Time
	broken   bool
	closed   bool
}

// Option configures a Log.
type Option func(*Log)

// WithCheckpointSigner arms Checkpoint and pins the log's identity
// (signer.LogID becomes Checkpoint.Origin, and the Prover refuses
// checkpoints of other origins).
func WithCheckpointSigner(cs tlog.CheckpointSigner) Option {
	return func(l *Log) { l.signer = &cs }
}

// WithClock overrides the checkpoint timestamp source (tests).
func WithClock(clock func() time.Time) Option {
	return func(l *Log) { l.clock = clock }
}

// New opens (creating if needed) the log rooted at dir, replaying and
// verifying the leaf journal. A truncated final line without its newline is
// an uncommitted append from a crash: truncated loudly and recovered. A
// complete-but-malformed line, a density break, or a leaf-hash mismatch is
// damage and refuses the open.
func New(dir string, opts ...Option) (*Log, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("merklelog: create %s: %w", dir, err)
	}
	path := filepath.Join(dir, journalName)
	// O_APPEND: every write lands at the current end of file regardless of
	// the handle's offset, so neither the replay read (which never moves
	// this handle) nor a rollback truncate can misplace a later append —
	// the offset failure class is structurally absent.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return nil, fmt.Errorf("merklelog: open %s: %w", path, err)
	}
	// Lock BEFORE replay so the single-opener guard covers the whole
	// read/truncate window.
	if err := lockFile(f); err != nil {
		f.Close()
		return nil, err
	}
	l := &Log{file: f, clock: time.Now}
	for _, opt := range opts {
		opt(l)
	}
	if err := l.replay(path); err != nil {
		f.Close()
		return nil, err
	}
	// Durability of the creation itself: a fresh directory entry needs its
	// own fsync or a crash can lose an acknowledged log wholesale.
	if err := fsyncDir(dir); err != nil {
		f.Close()
		return nil, err
	}
	if err := fsyncDir(filepath.Dir(dir)); err != nil {
		f.Close()
		return nil, err
	}
	return l, nil
}

func (l *Log) replay(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("merklelog: read %s: %w", path, err)
	}
	keep := int64(len(raw))
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		// Unterminated final fragment: appends fsync line-complete writes,
		// so this is provably an uncommitted append from a crash. Truncate
		// it loudly instead of refusing to open.
		cut := strings.LastIndexByte(string(raw), '\n') + 1
		if err := l.file.Truncate(int64(cut)); err != nil {
			return fmt.Errorf("merklelog: truncate torn tail of %s: %w", path, err)
		}
		fmt.Fprintf(os.Stderr, "merklelog: truncated torn tail (uncommitted append from a crash) path=%s kept_bytes=%d\n", path, cut)
		keep = int64(cut)
		raw = raw[:cut]
	}
	line := 0
	for len(raw) > 0 {
		nl := strings.IndexByte(string(raw), '\n')
		lineBytes := raw[:nl]
		raw = raw[nl+1:]
		line++
		var e entry
		if err := canon.NewStrictDecoder(lineBytes).Decode(&e); err != nil {
			return fmt.Errorf("merklelog: %s line %d: damaged entry: %w", path, line, err)
		}
		if e.V != 1 {
			return fmt.Errorf("merklelog: %s line %d: unsupported entry version %d", path, line, e.V)
		}
		if e.Index != uint64(line-1) {
			return fmt.Errorf("merklelog: %s line %d: index %d breaks density", path, line, e.Index)
		}
		leaf := rfc6962.LeafHash(e.Payload)
		if got := hex.EncodeToString(leaf[:]); got != e.Leaf {
			return fmt.Errorf("merklelog: %s line %d: leaf hash mismatch (tampered payload)", path, line)
		}
		l.payloads = append(l.payloads, e.Payload)
		l.leaves = append(l.leaves, leaf)
	}
	l.size = keep
	return nil
}

// Append durably appends payload: envelope line + fsync, then the in-memory
// tail. On a write or fsync failure the file is rolled back to the last
// committed length; if the rollback itself fails the log is poisoned so no
// append can follow a partial record.
func (l *Log) Append(_ context.Context, payload []byte) (*tlog.Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.broken {
		return nil, errors.New("merklelog: log poisoned after an unrecoverable append failure — refusing to append after a partial record")
	}
	if l.closed {
		return nil, errors.New("merklelog: append on a closed log")
	}
	stored := make([]byte, len(payload))
	copy(stored, payload)
	leaf := rfc6962.LeafHash(stored)
	e := entry{V: 1, Index: uint64(len(l.payloads)), Payload: stored, Leaf: hex.EncodeToString(leaf[:])}
	// canonicalizer-hygiene-exempt: local storage envelope, not a signing scope.
	line, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("merklelog: marshal entry %d: %w", e.Index, err)
	}
	if _, err := l.file.Write(append(line, '\n')); err != nil {
		l.rollback()
		return nil, fmt.Errorf("merklelog: append entry %d: %w", e.Index, err)
	}
	if err := l.file.Sync(); err != nil {
		l.rollback()
		return nil, fmt.Errorf("merklelog: fsync entry %d: %w", e.Index, err)
	}
	l.size += int64(len(line)) + 1
	l.payloads = append(l.payloads, stored)
	l.leaves = append(l.leaves, leaf)
	return &tlog.Record{Index: e.Index, Payload: append([]byte(nil), stored...), Hash: e.Leaf}, nil
}

// rollback truncates the file back to the last committed length after a
// failed write. If that also fails, the file may end in a partial record:
// poison the log so the damage surfaces instead of compounding.
func (l *Log) rollback() {
	if err := l.file.Truncate(l.size); err != nil {
		l.broken = true
	}
}

// Get returns the record at index (defensive copy).
func (l *Log) Get(_ context.Context, index uint64) (*tlog.Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if index >= uint64(len(l.payloads)) {
		return nil, fmt.Errorf("merklelog: index %d out of range (size %d)", index, len(l.payloads))
	}
	return &tlog.Record{
		Index:   index,
		Payload: append([]byte(nil), l.payloads[index]...),
		Hash:    hex.EncodeToString(l.leaves[index][:]),
	}, nil
}

// Size returns the number of committed records.
func (l *Log) Size(_ context.Context) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return uint64(len(l.payloads)), nil
}

// Checkpoint produces a signed commitment to the current Merkle root, or a
// wrapped tlog.ErrUnsignedLog when no signer is armed.
func (l *Log) Checkpoint(_ context.Context) (*tlog.Checkpoint, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.signer == nil {
		return nil, fmt.Errorf("merklelog: %w", tlog.ErrUnsignedLog)
	}
	root := rfc6962.Root(l.leaves)
	cp, err := tlog.SignCheckpoint(uint64(len(l.leaves)), hex.EncodeToString(root[:]), l.signer, l.clock().UTC().Truncate(time.Second))
	if err != nil {
		return nil, fmt.Errorf("merklelog: %w", err)
	}
	return cp, nil
}

// ProveInclusion returns the audit path for the record at index against cp
// (RFC 6962 §2.1.1). The checkpoint must be this log's own: its Origin must
// match the armed LogID, and its size must not exceed the committed size.
func (l *Log) ProveInclusion(_ context.Context, index uint64, cp *tlog.Checkpoint) (*tlog.InclusionProof, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.checkOwnCheckpoint(cp); err != nil {
		return nil, err
	}
	if index >= cp.Size {
		return nil, fmt.Errorf("merklelog: prove inclusion: index %d not below checkpoint size %d", index, cp.Size)
	}
	path := rfc6962.InclusionPath(l.leaves[:cp.Size], index)
	return &tlog.InclusionProof{LeafIndex: index, TreeSize: cp.Size, Path: flatten(path)}, nil
}

// ProveConsistency returns the append-only evidence between two of this
// log's checkpoints (RFC 6962 §2.1.2). Degenerate forms mirror
// tlog.VerifyConsistency: equal sizes and an older size of zero yield an
// empty path.
func (l *Log) ProveConsistency(_ context.Context, older, newer *tlog.Checkpoint) (*tlog.ConsistencyProof, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.checkOwnCheckpoint(older); err != nil {
		return nil, err
	}
	if err := l.checkOwnCheckpoint(newer); err != nil {
		return nil, err
	}
	if older.Size > newer.Size {
		return nil, fmt.Errorf("merklelog: prove consistency: older size %d exceeds newer size %d", older.Size, newer.Size)
	}
	proof := &tlog.ConsistencyProof{OldSize: older.Size, NewSize: newer.Size}
	if older.Size == newer.Size || older.Size == 0 {
		return proof, nil
	}
	proof.Path = flatten(rfc6962.ConsistencyPath(l.leaves[:newer.Size], older.Size))
	return proof, nil
}

func (l *Log) checkOwnCheckpoint(cp *tlog.Checkpoint) error {
	if cp == nil {
		return errors.New("merklelog: nil checkpoint")
	}
	if cp.Origin == "" {
		return errors.New("merklelog: checkpoint carries no origin")
	}
	if l.signer == nil || cp.Origin != l.signer.LogID {
		return fmt.Errorf("merklelog: checkpoint origin %q is not this log", cp.Origin)
	}
	if cp.Size > uint64(len(l.leaves)) {
		return fmt.Errorf("merklelog: checkpoint size %d exceeds log size %d", cp.Size, len(l.leaves))
	}
	// The head must commit to THIS log's state at cp.Size: a right-origin,
	// in-range checkpoint with a foreign head would otherwise yield proofs
	// that can never verify (or a vacuous empty consistency proof).
	root := rfc6962.Root(l.leaves[:cp.Size])
	if cp.Head != hex.EncodeToString(root[:]) {
		return fmt.Errorf("merklelog: checkpoint head does not commit to this log's state at size %d", cp.Size)
	}
	return nil
}

// Close releases the file handle and the single-opener lock.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return l.file.Close()
}

func flatten(path [][rfc6962.HashSize]byte) [][]byte {
	out := make([][]byte, len(path))
	for i := range path {
		out[i] = append([]byte(nil), path[i][:]...)
	}
	return out
}

// fsyncDir flushes a directory entry (file/dir creation durability).
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("merklelog: open dir %s: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("merklelog: fsync dir %s: %w", dir, err)
	}
	return nil
}
