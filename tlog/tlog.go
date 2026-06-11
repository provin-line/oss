// Package tlog defines the per-organization transparency log contract:
// append-only, tamper-evident, independently verifiable record sequences.
//
// There is no network-global log (per-peer trust root): each organization
// hosts its own logs under its own DID. The audit model's reconciliation
// mechanics rest on these logs being retained for the audit horizon —
// retention is a deployment obligation, not an optimization.
//
// Consumers:
//   - publisher emission logs (envelope hash + sequence number)
//   - ingress receipt logs (verified ingress credentials)
//   - persistent VC-store registration logs
//   - the cryptosuite lifecycle registry (packages/vc.LifecycleRegistry)
//
// The contract is designed for production from the start; implementations
// scale up without contract changes: a PoC implementation is a durable
// hash-chained file log (tamper-evident, no proofs); a CT-style Merkle
// implementation additionally provides the Prover capability for
// inclusion/consistency proofs without log replay.
package tlog

import (
	"context"
	"time"
)

// Record is one immutable log entry.
type Record struct {
	// Index is the zero-based position in the log.
	Index uint64
	// Payload is the opaque record content; consumers define the encoding.
	Payload []byte
	// Hash chains the log: sha256 over (previous record's Hash ‖ canonical
	// record bytes); the genesis record chains from a zero hash. Any
	// retroactive modification breaks every subsequent hash.
	Hash string
}

// Checkpoint is a signed commitment to the log state at Size records. The
// operator's signature makes the log head non-repudiable: having published a
// checkpoint, the operator cannot later present a different history below
// that size without detection.
type Checkpoint struct {
	Size uint64
	// Head is the commitment value: the chain head hash (hash-chain
	// implementations) or the Merkle root (tree implementations).
	Head      string
	Timestamp time.Time
	// SignedBy is the verification method DID URL of the signing key.
	SignedBy  string
	Signature []byte
}

// Log is the append-only contract. Implementations MUST be durable and MUST
// never mutate or delete appended records.
type Log interface {
	// Append durably appends payload and returns the committed record.
	Append(ctx context.Context, payload []byte) (*Record, error)
	// Get returns the record at index.
	Get(ctx context.Context, index uint64) (*Record, error)
	// Size returns the number of committed records.
	Size(ctx context.Context) (uint64, error)
	// Checkpoint produces a signed commitment to the current state.
	Checkpoint(ctx context.Context) (*Checkpoint, error)
}

// Proof is an inclusion or consistency proof path. Its interpretation is
// implementation-defined (Merkle audit path for tree logs); verification
// goes through the issuing implementation's verifier.
type Proof struct {
	Path [][]byte
}

// Prover is the optional capability of proof-supporting implementations
// (CT-style Merkle logs). Callers discover it by type assertion on a Log;
// hash-chain implementations may omit it, in which case auditors verify by
// replaying the chain segment instead.
type Prover interface {
	// ProveInclusion proves that the record at index is committed by cp.
	ProveInclusion(ctx context.Context, index uint64, cp *Checkpoint) (*Proof, error)
	// ProveConsistency proves that the log state committed by older is a
	// prefix of the state committed by newer (append-only evidence).
	ProveConsistency(ctx context.Context, older, newer *Checkpoint) (*Proof, error)
}
