// Package filelog is the durable PoC implementation of tlog.Log: an
// append-only, hash-chained NDJSON file, replay-verified at open. It is the
// implementation the tlog contract names for deployments ("a durable
// hash-chained file log — tamper-evident, no proofs"); memlog remains the
// in-memory twin, and the shared contract suite keeps the two from
// drifting.
//
// Checkpoints: armed with a CheckpointSigner, Checkpoint signs the JCS
// canonicalization of the versioned, domain-separated view
// {v:1, purpose:"dplaax-tlog-checkpoint", logId, head, signedBy, size,
// timestamp} — logId inside the signature means a checkpoint from one log
// can never be presented as another's, and purpose/v separate it from
// every other signature the key produces. Unarmed, Checkpoint returns
// ErrUnsignedLog (a typed error, never an unsigned value that looks like a
// commitment).
package filelog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/canon/jcs"
	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/tlog"
)

// ErrUnsignedLog is returned by Checkpoint on a log opened without a
// CheckpointSigner: it cannot produce the signed commitment the tlog.Log
// contract requires, and a typed error keeps a caller from mistaking the
// absence of a signature for a verified log head.
var ErrUnsignedLog = fmt.Errorf("filelog: signed checkpoints require WithCheckpointSigner: %w", tlog.ErrUnsignedLog)

// ErrLocked is returned by New when another live opener already holds the
// directory's single-opener lock (an flock on the append file). It is a
// filelog-LOCAL sentinel — single-opener locking is a durable-file mechanism
// with no memlog analogue, so unlike ErrUnsignedLog it is not a tlog contract
// condition. Detect with errors.Is; a second node process on one data-dir
// fails boot with it instead of silently forking the chain.
var ErrLocked = errors.New("filelog: log directory is locked by another opener")

const logFile = "log.ndjson"

// intentFile holds the durable emission-sequence high-water (see RecordIntent);
// intentTmpFile is its atomic-rename staging name.
const (
	intentFile    = "intent"
	intentTmpFile = "intent.tmp"
)

// checkpointPurpose domain-separates checkpoint signatures from every other
// signature the same key produces.
const checkpointPurpose = "dplaax-tlog-checkpoint"

// entry is the on-disk shape of one record: a versioned envelope so a later
// format change can migrate instead of guessing. Payload round-trips
// through encoding/json's base64 for []byte.
type entry struct {
	V       int    `json:"v"`
	Index   uint64 `json:"index"`
	Payload []byte `json:"payload"`
	Hash    string `json:"hash"`
}

// CheckpointSigner arms a Log to sign its head commitments: the signing
// capability (the repo's DID-aware crypto.Signer), the key address
// (SignerDID + KeyID), the verification-method DID URL served as SignedBy,
// and the log identity bound INSIDE every signature.
type CheckpointSigner struct {
	Signer             crypto.Signer
	SignerDID          string
	KeyID              string
	VerificationMethod string
	LogID              string
}

// Option configures a Log.
type Option func(*Log)

// WithCheckpointSigner arms Checkpoint (see CheckpointSigner).
func WithCheckpointSigner(cs CheckpointSigner) Option {
	return func(l *Log) { l.signer = &cs }
}

// Log is the file-backed tlog.Log. Construct with New; Close releases the
// file handle AND the single-opener lock. A directory has at most ONE live
// opener: New takes an exclusive advisory flock on the append file before
// touching the chain, so a second opener gets ErrLocked rather than
// interleaving two chains and bricking the next open. The guard is
// cross-process (and cross-open); it does not stop a caller from sharing one
// *Log across goroutines — that is what mu is for.
type Log struct {
	mu      sync.Mutex
	file    *os.File
	dir     string
	size    int64 // committed file length in bytes
	records []*tlog.Record
	signer  *CheckpointSigner
	// intent is the durable emission-sequence high-water loaded at New and
	// advanced by RecordIntent (0 if none). It is the ONLY in-memory copy of
	// the last DURABLY persisted value — advanced strictly after the fsync.
	intent uint64
	// broken poisons Append after a failed write could not be rolled back:
	// continuing would append after a partial line, making the log
	// unreadable at the next open.
	broken bool
	closed bool
}

var _ tlog.Log = (*Log)(nil)

// New opens (creating if needed) the log rooted at dir, replaying and
// verifying the existing chain: every record's index must be dense and its
// hash must recompute — a log that cannot prove its own chain fails open
// (evidence doctrine: damage is loud, never absence). O(n) open cost is
// the PoC trade; the contract lets an implementation add snapshotting.
func New(dir string, opts ...Option) (*Log, error) {
	// Pin dir to an absolute path up front: the Log holds it for the life of
	// the process (persistIntent joins against it on every RecordIntent), and
	// a caller-relative path would silently re-resolve against a LATER working
	// directory — writing the intent sidecar beside the wrong dir and losing
	// the anti-reuse high-water exactly when recovery needs it.
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("filelog: resolve %s: %w", dir, err)
	}
	// 0700/0600: emission records are evidence, gated on the wire by
	// tlog/read — local permissions must not hand out what the
	// authorization surface protects.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("filelog: create %s: %w", dir, err)
	}
	path := filepath.Join(dir, logFile)
	// Open BEFORE replay so the single-opener lock is held over the whole
	// read/truncate: two concurrent New calls must not both replay and both
	// grow the same chain.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("filelog: open %s for append: %w", path, err)
	}
	// Every constructor error path AFTER this point runs holding the flock;
	// each must release the fd (closing it drops the lock) or the lock leaks
	// until GC/process exit and blocks later openers. One defer covers them
	// all — success flips only on the fully constructed Log.
	success := false
	defer func() {
		if !success {
			_ = f.Close()
		}
	}()
	if err := lockFile(f); err != nil {
		return nil, fmt.Errorf("filelog: open %s: %w", dir, err)
	}
	records, keep, err := replay(path)
	if err != nil {
		return nil, err
	}
	if keep >= 0 {
		// Torn tail from a crash mid-append: every COMPLETE line was
		// fsynced, so an unterminated final fragment is provably an
		// uncommitted append — truncate it loudly instead of refusing to
		// boot forever. (Interior damage still fails open above.)
		if err := f.Truncate(keep); err != nil {
			return nil, fmt.Errorf("filelog: truncate torn tail of %s: %w", path, err)
		}
		slog.Warn("filelog: truncated torn tail (uncommitted append from a crash)", "path", path, "kept_bytes", keep)
	}
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("filelog: stat %s: %w", path, err)
	}
	// Durability of the CREATION itself: Append fsyncs the file, but a
	// fresh directory entry (and the hashed dir under its parent) needs its
	// own fsync or a crash can lose an acknowledged log wholesale.
	if err := fsyncDir(dir); err != nil {
		return nil, err
	}
	if err := fsyncDir(filepath.Dir(dir)); err != nil {
		return nil, err
	}
	intent, err := loadIntent(dir)
	if err != nil {
		return nil, err
	}
	l := &Log{file: f, dir: dir, size: fi.Size(), records: records, intent: intent}
	for _, opt := range opts {
		opt(l)
	}
	success = true
	return l, nil
}

// loadIntent reads the durable emission-sequence high-water. The load is
// 3-way (see RecordIntent for the doctrine): a MISSING file is 0 (normal first
// run); a PRESENT but unparseable file degrades to 0 with a loud log — the
// explicit availability-over-anti-reuse exception, since a corrupt operational
// hint must not brick a node whose chain evidence may be intact, and recovery
// then falls back to the tail (never below it); a real READ I/O error fails
// New — a sick disk should be loud, not silently trusted.
func loadIntent(dir string) (uint64, error) {
	raw, err := os.ReadFile(filepath.Join(dir, intentFile))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("filelog: read intent %s: %w", dir, err)
	}
	seq, perr := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if perr != nil {
		slog.Error("filelog: intent high-water unparseable — anti-reuse degraded to baseline (chain evidence unaffected)",
			"dir", dir, "err", perr)
		return 0, nil
	}
	return seq, nil
}

// fsyncDir flushes a directory entry (file/dir creation durability).
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("filelog: open dir %s for fsync: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("filelog: fsync dir %s: %w", dir, err)
	}
	return nil
}

// Close releases the file handle; subsequent Appends fail.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return l.file.Close()
}

// replay reads and verifies the whole chain from path; a missing file is an
// empty log. keep >= 0 reports a torn final fragment (crash mid-append):
// the byte length of the COMPLETE prefix the caller should truncate to.
// Whole-file read: no per-line size limit can brick a reopen.
func replay(path string) (records []*tlog.Record, keep int64, err error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, -1, nil
	}
	if err != nil {
		return nil, -1, fmt.Errorf("filelog: read %s: %w", path, err)
	}
	keep = -1
	if n := len(raw); n > 0 && raw[n-1] != '\n' {
		cut := strings.LastIndexByte(string(raw), '\n') + 1
		keep = int64(cut)
		raw = raw[:cut]
	}
	prev := ""
	line := 0
	for len(raw) > 0 {
		nl := strings.IndexByte(string(raw), '\n')
		lineBytes := raw[:nl]
		raw = raw[nl+1:]
		line++
		var e entry
		if err := canon.NewStrictDecoder(lineBytes).Decode(&e); err != nil {
			return nil, -1, fmt.Errorf("filelog: %s line %d: damaged entry: %w", path, line, err)
		}
		if e.V != 1 {
			return nil, -1, fmt.Errorf("filelog: %s line %d: unsupported entry version %d", path, line, e.V)
		}
		if e.Index != uint64(line-1) {
			return nil, -1, fmt.Errorf("filelog: %s line %d: index %d breaks density", path, line, e.Index)
		}
		if got := chainHash(prev, e.Payload); got != e.Hash {
			return nil, -1, fmt.Errorf("filelog: %s line %d: chain hash mismatch (tampered or truncated-and-regrown)", path, line)
		}
		records = append(records, &tlog.Record{Index: e.Index, Payload: e.Payload, Hash: e.Hash})
		prev = e.Hash
	}
	return records, keep, nil
}

// marshalEntry serializes one on-disk envelope. Local storage bytes, never
// hashed or signed over as-is — the chain hash covers the payload and the
// checkpoint signs the JCS view, so canonical form is not required here.
func marshalEntry(e entry) ([]byte, error) {
	// canonicalizer-hygiene-exempt: local storage envelope, not a signing scope.
	return json.Marshal(e)
}

// chainHash is the pinned commitment formula shared with memlog:
// sha256( []byte(prevHashHex) ‖ payload ), genesis prevHashHex = "".
func chainHash(prev string, payload []byte) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

func clone(rec *tlog.Record) *tlog.Record {
	p := make([]byte, len(rec.Payload))
	copy(p, rec.Payload)
	return &tlog.Record{Index: rec.Index, Payload: p, Hash: rec.Hash}
}

// Append durably appends payload: envelope line + fsync, then the in-memory
// tail. A write failure surfaces to the caller (the emitter's
// append-after-publish already treats that as its logged-only audit-defense
// loss — unchanged posture).
func (l *Log) Append(_ context.Context, payload []byte) (*tlog.Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	prev := ""
	if n := len(l.records); n > 0 {
		prev = l.records[n-1].Hash
	}
	stored := make([]byte, len(payload))
	copy(stored, payload)
	rec := &tlog.Record{
		Index:   uint64(len(l.records)),
		Payload: stored,
		Hash:    chainHash(prev, stored),
	}
	if l.broken {
		return nil, errors.New("filelog: log poisoned after an unrecoverable append failure — refusing to append after a partial line")
	}
	if l.closed {
		return nil, errors.New("filelog: append on a closed log")
	}
	line, err := marshalEntry(entry{V: 1, Index: rec.Index, Payload: stored, Hash: rec.Hash})
	if err != nil {
		return nil, fmt.Errorf("filelog: marshal entry %d: %w", rec.Index, err)
	}
	if _, err := l.file.Write(append(line, '\n')); err != nil {
		l.rollback()
		return nil, fmt.Errorf("filelog: append entry %d: %w", rec.Index, err)
	}
	if err := l.file.Sync(); err != nil {
		l.rollback()
		return nil, fmt.Errorf("filelog: fsync entry %d: %w", rec.Index, err)
	}
	l.size += int64(len(line)) + 1
	l.records = append(l.records, rec)
	return clone(rec), nil
}

// rollback truncates the file back to the last committed length after a
// failed write, so the file and the in-memory state stay consistent. If the
// truncate itself fails, the log is POISONED: a partial line may sit on
// disk, and appending after it would produce a file no replay can read —
// failing every later Append loudly is the honest posture. Callers hold mu.
func (l *Log) rollback() {
	if err := l.file.Truncate(l.size); err != nil {
		l.broken = true
		slog.Error("filelog: rollback truncate failed — log poisoned for further appends", "err", err)
	}
}

// RecordIntent durably records seq as the highest emission sequence number an
// emitter is ABOUT TO publish, so a crash in the emitter's publish→append
// window can never let recovery re-issue seq to a different event (see
// pipeline/transport.Emitter). It is the optional durable-sequence-intent
// capability the emitter probes for; memlog does not provide it.
//
// The in-memory high-water advances ONLY after the full fsync chain succeeds,
// and l.intent is the last DURABLY persisted value: a seq at or below it is a
// no-op, but a seq above it that fails to persist leaves l.intent unchanged so
// the emitter's retry re-persists rather than short-circuiting — otherwise a
// failed RecordIntent could let a publish proceed with no durable intent
// behind it.
func (l *Log) RecordIntent(_ context.Context, seq uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("filelog: record intent on a closed log")
	}
	if seq <= l.intent {
		return nil // monotonic; never regress below the last durable value.
	}
	// Deliberately NOT gated on l.broken: the intent sidecar is independent of
	// chain integrity — a poisoned chain refuses APPENDS, but recording the
	// anti-reuse high-water stays both safe and useful for the next boot.
	if err := l.persistIntent(seq); err != nil {
		return err // cache NOT advanced → a retry re-persists, not a no-op.
	}
	l.intent = seq
	return nil
}

// HighestIntent returns the durable high-water (0 if none) — the read half of
// the intent capability, used by emitter recovery to skip past sequence
// numbers that were attempted but not yet committed to the chain.
func (l *Log) HighestIntent(_ context.Context) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.intent, nil
}

// persistIntent atomically replaces the intent file with seq: same-dir temp →
// write → fsync → checked close → rename → fsync(dir). Atomic rename keeps the
// intent file always holding a COMPLETE prior value (never a torn write); the
// fsync chain makes the new value durable before return, so if RecordIntent
// returns before the caller publishes, a post-crash reopen reads high-water
// >= seq. Caller holds l.mu.
func (l *Log) persistIntent(seq uint64) error {
	tmp := filepath.Join(l.dir, intentTmpFile)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("filelog: create intent tmp: %w", err)
	}
	if _, err := f.Write([]byte(strconv.FormatUint(seq, 10))); err != nil {
		_ = f.Close()
		return fmt.Errorf("filelog: write intent tmp: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("filelog: fsync intent tmp: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("filelog: close intent tmp: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(l.dir, intentFile)); err != nil {
		return fmt.Errorf("filelog: rename intent: %w", err)
	}
	return fsyncDir(l.dir)
}

// Get returns the record at index, or an error if index is out of range.
func (l *Log) Get(_ context.Context, index uint64) (*tlog.Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if index >= uint64(len(l.records)) {
		return nil, fmt.Errorf("filelog: index %d out of range (size %d)", index, len(l.records))
	}
	return clone(l.records[index]), nil
}

// Size returns the number of committed records.
func (l *Log) Size(_ context.Context) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return uint64(len(l.records)), nil
}

// Checkpoint produces the signed head commitment, or ErrUnsignedLog when
// the log was opened without a CheckpointSigner.
func (l *Log) Checkpoint(_ context.Context) (*tlog.Checkpoint, error) {
	l.mu.Lock()
	size := uint64(len(l.records))
	head := ""
	if size > 0 {
		head = l.records[size-1].Hash
	}
	signer := l.signer
	l.mu.Unlock()
	if signer == nil {
		return nil, ErrUnsignedLog
	}
	ts := time.Now().UTC().Truncate(time.Second)
	view, err := jcs.Canonicalize(map[string]any{
		"v":         1,
		"purpose":   checkpointPurpose,
		"logId":     signer.LogID,
		"head":      head,
		"signedBy":  signer.VerificationMethod,
		"size":      strconv.FormatUint(size, 10),
		"timestamp": ts.Format(time.RFC3339),
	})
	if err != nil {
		return nil, fmt.Errorf("filelog: canonicalize checkpoint view: %w", err)
	}
	sig, err := signer.Signer.Sign(signer.SignerDID, signer.KeyID, view)
	if err != nil {
		return nil, fmt.Errorf("filelog: sign checkpoint: %w", err)
	}
	return &tlog.Checkpoint{
		Size:      size,
		Head:      head,
		Timestamp: ts,
		SignedBy:  signer.VerificationMethod,
		Signature: sig,
	}, nil
}
