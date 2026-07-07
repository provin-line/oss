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

const logFile = "log.ndjson"

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
// file handle. A directory must have at most ONE opener at a time — two
// processes appending to one log would interleave two chains and brick the
// next open (single-opener is the node's boot invariant; an flock-style
// guard is a recorded follow-up).
type Log struct {
	mu      sync.Mutex
	file    *os.File
	size    int64 // committed file length in bytes
	records []*tlog.Record
	signer  *CheckpointSigner
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
	// 0700/0600: emission records are evidence, gated on the wire by
	// tlog/read — local permissions must not hand out what the
	// authorization surface protects.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("filelog: create %s: %w", dir, err)
	}
	path := filepath.Join(dir, logFile)
	records, keep, err := replay(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("filelog: open %s for append: %w", path, err)
	}
	if keep >= 0 {
		// Torn tail from a crash mid-append: every COMPLETE line was
		// fsynced, so an unterminated final fragment is provably an
		// uncommitted append — truncate it loudly instead of refusing to
		// boot forever. (Interior damage still fails open above.)
		if err := f.Truncate(keep); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("filelog: truncate torn tail of %s: %w", path, err)
		}
		slog.Warn("filelog: truncated torn tail (uncommitted append from a crash)", "path", path, "kept_bytes", keep)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("filelog: stat %s: %w", path, err)
	}
	// Durability of the CREATION itself: Append fsyncs the file, but a
	// fresh directory entry (and the hashed dir under its parent) needs its
	// own fsync or a crash can lose an acknowledged log wholesale.
	if err := fsyncDir(dir); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := fsyncDir(filepath.Dir(dir)); err != nil {
		_ = f.Close()
		return nil, err
	}
	l := &Log{file: f, size: fi.Size(), records: records}
	for _, opt := range opts {
		opt(l)
	}
	return l, nil
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
