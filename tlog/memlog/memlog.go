// Package memlog is a minimal in-memory tlog.Log: an append-only, hash-chained,
// tamper-evident record sequence held in memory. It is the PoC Emission seam for
// pipeline producing loops (transport.Loop requires a tlog.Log for credential-hash
// + sequence-number emission).
//
// Scope: memlog is NOT durable (records are lost on restart) and produces NO signed
// checkpoints — Checkpoint returns ErrUnsignedLog. The durable hash-chained file
// log and the CT-style Merkle log (signed Checkpoint + Prover inclusion/consistency
// proofs) are the transparency-log epic; memlog deliberately implements only the
// append-and-replay core so the contract is exercised end-to-end without pulling
// that epic forward.
package memlog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/provin-line/oss/tlog"
)

// ErrUnsignedLog is returned by Checkpoint: an in-memory log has no signer, so it
// cannot produce the signed commitment the tlog.Log contract requires. Returning a
// typed error (rather than an unsigned value that looks like a checkpoint) keeps a
// caller from mistaking the absence of a signature for a verified log head.
var ErrUnsignedLog = errors.New("memlog: signed checkpoints require the tree-log implementation")

// Log is an in-memory, append-only, hash-chained tlog.Log. The zero value is not
// usable; construct with New.
type Log struct {
	mu      sync.Mutex
	records []*tlog.Record
}

// New returns an empty in-memory log.
func New() *Log { return &Log{} }

var _ tlog.Log = (*Log)(nil)

// chainHash is the documented commitment: sha256 over (prev ‖ payload). The genesis
// record chains from the empty hash, so every record's Hash transitively commits to
// the full prefix — any retroactive change breaks the chain from that point on.
func chainHash(prev string, payload []byte) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

// Append appends a copy of payload and returns the committed record. The record's
// Index is its zero-based position; its Hash chains from the previous record.
func (l *Log) Append(_ context.Context, payload []byte) (*tlog.Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var prev string
	if n := len(l.records); n > 0 {
		prev = l.records[n-1].Hash
	}
	// Copy the payload so a caller mutating its slice cannot alter a committed
	// record (records MUST never mutate — tlog.Log contract).
	stored := make([]byte, len(payload))
	copy(stored, payload)

	rec := &tlog.Record{
		Index:   uint64(len(l.records)),
		Payload: stored,
		Hash:    chainHash(prev, stored),
	}
	l.records = append(l.records, rec)
	return rec, nil
}

// Get returns the record at index, or an error if index is out of range.
func (l *Log) Get(_ context.Context, index uint64) (*tlog.Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if index >= uint64(len(l.records)) {
		return nil, fmt.Errorf("memlog: index %d out of range (size %d)", index, len(l.records))
	}
	return l.records[index], nil
}

// Size returns the number of committed records.
func (l *Log) Size(_ context.Context) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return uint64(len(l.records)), nil
}

// Checkpoint always returns ErrUnsignedLog: an in-memory log has no signing key, so
// it cannot produce the signed commitment the contract requires. See ErrUnsignedLog.
func (l *Log) Checkpoint(_ context.Context) (*tlog.Checkpoint, error) {
	return nil, ErrUnsignedLog
}
