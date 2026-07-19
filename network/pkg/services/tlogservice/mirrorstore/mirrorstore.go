// Package mirrorstore is the registry-side durable mirror of remote
// signed-hash-chain logs (spec: 2026-07-19-tlog-custody.md, D-T4): custody,
// not production. A background shipper on each pipeline process (D-T6)
// replicates checkpoint-aligned segments here; this store never signs,
// never synthesizes, and never re-derives a checkpoint — every Checkpoint
// value it serves is the exact REMOTE loop-signed value it was handed (all
// six tlog.Checkpoint fields, including Signature and SignedBy).
//
// Layout: one directory per log under root, named by the hex-encoded
// sha256 of the log id (log ids are DIDs / DID-prefixed strings, not
// filesystem-safe on their own — see dirName). Each log directory holds:
//
//	records.ndjson   — the hash-chained records journal, one JSON envelope
//	                   per line, fsynced on every append. Shape and
//	                   fsync / replay-verify-on-open discipline mirror
//	                   tlog/filelog.go's `entry` / `replay` / `Append` (the
//	                   SOURCE OF TRUTH for this on-disk format) — this
//	                   package cannot import filelog's unexported
//	                   internals, so it is an independent implementation of
//	                   the identical documented envelope, not a fork of
//	                   behavior.
//	checkpoint.json  — the persisted REMOTE checkpoint, verbatim.
//
// Hash chain: sha256(prevHexString ‖ payload), genesis previous = "" — the
// exact formula documented on tlog/tlog.go's Record.Hash and implemented
// independently by tlog/filelog and tlog/memlog (each carries its own
// unexported copy; import boundaries keep the implementations independent).
// This package's copy is ChainHash, EXPORTED — Task 5's MirrorLogSegment
// handler recomputes the identical chain head with it for D-T2 acceptance
// rule 1, so the accept-time check and this store's own defense-in-depth
// re-check can never silently disagree about the formula.
//
// Crash ordering (D-T4): AppendVerified fsyncs new records to the journal
// BEFORE it atomically replaces the checkpoint file (tmp + fsync + rename +
// dir-fsync — see writeAtomic, mirroring every other durable store in this
// repo). Reopen recovery in Open / openLogDir replay-verifies each log's
// journal and truncates anything beyond the persisted checkpoint's Size:
// those records were appended but never acked, so the shipper's resume
// (cursored on AckedSize / GetMirrorState.acked_size, never
// GetLogCheckpoint — D-T2 rule 6) reships them. A journal SHORTER than the
// checkpoint's size, or one whose recorded chain at that size does not
// match the checkpoint's Head, is damage this store cannot repair: that
// one log is marked POISONED (every subsequent call for it errors) without
// failing Open for the rest of the store — the same poisoning ethos as
// tlog/filelog.go's `broken` flag and tlog/merklelog's fault-injection
// tests (a damaged log fails loud and stays loud; it is never silently
// dropped or served short).
//
// Reads (Get, Size, AckedSize, Checkpoint) serve ONLY the verified prefix:
// by the crash-ordering guarantee above, every record held in memory after
// Open is also acked, so "verified" and "acked" are the same size here.
//
// Single-process assumption: like
// network/pkg/services/auditor/filestore's stores, Store assumes
// SINGLE-PROCESS ownership of root — one sync.RWMutex serializes every
// log's reads and writes within this process, with no cross-process file
// lock. Running two registry processes against the same
// DataDir/tlog-mirrors root is not supported.
//
// Byte-identical replay of an already-acked segment (D-T2 rule 2) is
// resolved by the CALLER, not here: AppendVerified has no from_index
// parameter, so a request must already be reduced to an exact extension
// (cp.Size == current acked size + len(records)) before it reaches this
// store. A handler that recognizes a wire request as a full replay of
// already-committed data returns success from AckedSize/Get comparisons
// without ever calling AppendVerified.
package mirrorstore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/provin-line/oss/tlog"
)

// ErrNotFound is returned by Checkpoint for a log this store has never
// mirrored, or has mirrored but never yet durably checkpointed (acked size
// 0) — both read as "no checkpoint to serve," the same posture
// network/pkg/services/tlogservice.Service.Checkpoint's local-log path
// takes for an absent log.
var ErrNotFound = errors.New("mirrorstore: no checkpoint recorded for that log")

// ErrConflict is AppendSegment's D-T2 rule 1/2 "does not align" failure that
// is NOT a malformed-request error: a from_index gap ahead of the acked
// size, a partial overlap with already-mirrored records (a replay whose
// payloads do not byte-match what is already stored, or a range that extends
// past the acked size), or a recomputed chain head that does not equal the
// checkpoint's head. The tlogservice.Service maps it to its own
// ErrMirrorConflict (→ connect FailedPrecondition); the store owns this
// resolution so replay-vs-conflict is decided atomically under the same lock
// the append itself holds (no torn read between "is this a replay?" and "commit").
var ErrConflict = errors.New("mirrorstore: segment does not align with the mirrored log")

// ErrSignerMismatch is AppendSegment's D-T3 first-writer-pin failure: a
// segment whose checkpoint SignedBy differs from the SignedBy of the
// checkpoint already stored for this log. The pin is enforced HERE, under the
// same lock the append holds, so two concurrent INITIAL segments from
// different (each individually ancestry-valid) sibling signers cannot both
// observe "no checkpoint yet" and both be accepted — the first to commit pins
// the signer, and the second sees that committed value. The tlogservice.Service
// maps it to its own ErrIdentityMismatch (→ connect PermissionDenied).
var ErrSignerMismatch = errors.New("mirrorstore: segment signer does not match the log's pinned signer")

// logEntry is the in-memory state for one mirrored log, keyed by
// dirName(logID) in Store.logs. poisonErr, once set at Open, is returned
// verbatim (wrapped with the failing call's context) by every subsequent
// read or write for this log: a damaged mirror stays loudly broken rather
// than silently serving a truncated or absent view.
type logEntry struct {
	dir       string
	records   []*tlog.Record
	cp        *tlog.Checkpoint
	poisonErr error
}

// Store is the registry-side mirror of remote emission/receipt/reject logs
// (spec D-T4): one directory per log under root. See the package doc for
// layout, crash ordering, and the single-process assumption.
type Store struct {
	mu   sync.RWMutex
	root string
	logs map[string]*logEntry
}

// dirName maps a log id to its on-disk directory name: the hex-encoded
// sha256 of the id. Log ids are DIDs or DID-prefixed strings (e.g.
// "sink-receipt:did:dplaax:..."), which are not safe to use directly as
// path components (colons, method-specific characters). The mapping is
// one-way BY DESIGN: Store never needs to recover a log id from a
// directory name — every public method is keyed by the log id the caller
// supplies, and the persisted checkpoint's own Origin field (when one
// exists) carries the id for diagnostics.
func dirName(logID string) string {
	sum := sha256.Sum256([]byte(logID))
	return hex.EncodeToString(sum[:])
}

// cloneRecord returns a deep copy of rec (copied Payload) so a value
// returned to a caller shares no mutable state with the store's internal
// record — the same defensive copy tlog/filelog.go and tlog/memlog.go make
// on every Get.
func cloneRecord(rec *tlog.Record) *tlog.Record {
	p := make([]byte, len(rec.Payload))
	copy(p, rec.Payload)
	return &tlog.Record{Index: rec.Index, Payload: p, Hash: rec.Hash}
}

// cloneCheckpoint returns a deep copy of cp (copied Signature) for the same
// reason cloneRecord copies Payload: a caller must not be able to mutate
// the store's internal checkpoint through the returned/stored value.
func cloneCheckpoint(cp *tlog.Checkpoint) *tlog.Checkpoint {
	if cp == nil {
		return nil
	}
	sig := make([]byte, len(cp.Signature))
	copy(sig, cp.Signature)
	out := *cp
	out.Signature = sig
	return &out
}

// AckedSize returns the number of records durably committed (appended AND
// checkpointed) for logID — the acked_size cursor GetMirrorState serves
// (D-T2 rule 6: the shipper's ONLY valid resume cursor; GetLogCheckpoint is
// never used as one). A log this store has never mirrored returns (0,
// nil): indistinguishable, by design, from a log that has shipped nothing
// yet — a fresh shipper's very first call must be able to start at 0
// without first discovering whether the registry has heard of the log. A
// POISONED log (see the package doc) returns an error instead of a number:
// 0 would misreport actual disk damage as "nothing shipped yet."
func (s *Store) AckedSize(logID string) (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.logs[dirName(logID)]
	if !ok {
		return 0, nil
	}
	if e.poisonErr != nil {
		return 0, fmt.Errorf("mirrorstore: acked size %q: %w", logID, e.poisonErr)
	}
	return uint64(len(e.records)), nil
}

// Size is AckedSize under the name a read path expects: Task 5 pairs
// Get(logID, index) with Size(logID) the same way every tlog.Log
// implementation pairs its own Get/Size (tlog/tlog.go's Log interface) — a
// caller enumerating [0, Size) never needs to reason about
// "acknowledgement" as a separate concept. The two names return the SAME
// value: by construction (AppendVerified's crash ordering), records fsync
// before a checkpoint durably advances the acked size, so nothing is ever
// readable that is not also acked.
func (s *Store) Size(logID string) (uint64, error) {
	return s.AckedSize(logID)
}

// Checkpoint returns the persisted REMOTE checkpoint for logID verbatim —
// every field this store received it with, never re-derived or re-signed
// — or a wrapped ErrNotFound for a log never mirrored, or mirrored but
// never yet checkpointed. A POISONED log returns its poison error, never
// ErrNotFound (damage must not read as "nothing to report yet").
func (s *Store) Checkpoint(logID string) (*tlog.Checkpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.logs[dirName(logID)]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNotFound, logID)
	}
	if e.poisonErr != nil {
		return nil, fmt.Errorf("mirrorstore: checkpoint %q: %w", logID, e.poisonErr)
	}
	if e.cp == nil {
		return nil, fmt.Errorf("%w: %q", ErrNotFound, logID)
	}
	return cloneCheckpoint(e.cp), nil
}

// Get returns the record at index for logID — served only from the
// verified (acked) prefix, since e.records never holds more than the
// checkpointed size (AppendVerified's crash ordering plus Open's reopen
// truncation guarantee this). Out of range — including every index on an
// unknown or zero-size log — is an error, the same posture as every
// tlog.Log implementation's own Get (tlog/filelog.go, tlog/memlog.go). A
// POISONED log returns its poison error.
func (s *Store) Get(logID string, index uint64) (*tlog.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.logs[dirName(logID)]
	if !ok {
		return nil, fmt.Errorf("mirrorstore: get %q[%d]: unknown log (size 0)", logID, index)
	}
	if e.poisonErr != nil {
		return nil, fmt.Errorf("mirrorstore: get %q[%d]: %w", logID, index, e.poisonErr)
	}
	if index >= uint64(len(e.records)) {
		return nil, fmt.Errorf("mirrorstore: get %q[%d]: out of range (size %d)", logID, index, len(e.records))
	}
	return cloneRecord(e.records[index]), nil
}
