// Package evidence is the chain manager's relationship-evidence log: the
// durable, append-only record of a counterparty-signed control-plane
// request plus the key material used to verify it (transfer.relationship.record).
// It is a thin JSON codec over tlog.Log — durability, append-only ordering,
// and tamper-evidence all come from the wrapped log; this package owns only
// the retained shape and its (de)serialization.
package evidence

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/tlog"
)

// Record is one retained relationship-evidence entry: a counterparty-signed
// control-plane request plus the key material used to verify it, enough for a
// third party to re-derive the signed view and re-check the signature.
type Record struct {
	Op          string         `json:"op"`          // the wireauth view discriminator ("RegisterSubscription" / "Disconnect")
	ViewVersion int            `json:"viewVersion"` // echoes wireauth.ViewVersion — the "v" in the signed view; a reconstructor places it under key "v" when rebuilding the JCS view
	SignerDID   string         `json:"signerDID"`
	Nonce       string         `json:"nonce"`
	IssuedAt    string         `json:"issuedAt"` // RFC3339, second-precision (as it was signed)
	Signature   []byte         `json:"signature"`
	Fields      map[string]any `json:"fields"`      // the exact business fields that were signed
	KeyMaterial KeyMaterial    `json:"keyMaterial"` // snapshot of the verifying key
}

// KeyMaterial is the snapshot of the verification key the signature was checked
// against (so the retained record is self-contained for re-verification).
type KeyMaterial struct {
	Method    string `json:"method"`    // verification method DID URL (e.g. "<did>#auth")
	PublicKey []byte `json:"publicKey"` // raw public key bytes
	Type      string `json:"type"`      // key type / relationship as resolved
}

// Log is the durable, append-only relationship-evidence log. It wraps a
// tlog.Log; construct with New.
type Log struct {
	log tlog.Log
}

// New returns a Log backed by log.
func New(log tlog.Log) *Log {
	return &Log{log: log}
}

// Record JSON-marshals r and durably appends it, returning the committed
// tlog record (its Index is the record's position; retrieve it again with
// Get).
func (l *Log) Record(ctx context.Context, r Record) (*tlog.Record, error) {
	// A local storage envelope, never hashed or signed over as-is (the
	// underlying tlog's chain hash covers these bytes; canonical form is not
	// required here) — canonicalizer-hygiene-exempt.
	b, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("evidence: marshal record: %w", err)
	}
	rec, err := l.log.Append(ctx, b)
	if err != nil {
		return nil, fmt.Errorf("evidence: append record: %w", err)
	}
	return rec, nil
}

// Get returns the record at index, decoded from the underlying tlog entry.
func (l *Log) Get(ctx context.Context, index uint64) (Record, error) {
	rec, err := l.log.Get(ctx, index)
	if err != nil {
		return Record{}, fmt.Errorf("evidence: get record %d: %w", index, err)
	}
	var r Record
	if err := canon.NewStrictDecoder(rec.Payload).Decode(&r); err != nil {
		return Record{}, fmt.Errorf("evidence: decode record %d: %w", index, err)
	}
	return r, nil
}

// Size returns the number of committed records (delegates to the underlying
// tlog.Log).
func (l *Log) Size(ctx context.Context) (uint64, error) {
	n, err := l.log.Size(ctx)
	if err != nil {
		return 0, fmt.Errorf("evidence: size: %w", err)
	}
	return n, nil
}
