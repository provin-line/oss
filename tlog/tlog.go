// Package tlog defines the per-organization transparency log contract:
// append-only, tamper-evident, independently verifiable record sequences.
//
// There is no network-global log (per-peer trust root): each organization
// hosts its own logs under its own DID. The audit model's reconciliation
// mechanics rest on these logs being retained for the audit horizon —
// retention is a deployment obligation, not an optimization.
//
// Consumers:
//   - publisher emission logs (credential hash + sequence number)
//   - ingress receipt logs (verified ingress credentials)
//   - persistent VC-store registration logs
//   - the cryptosuite lifecycle registry (vc.LifecycleRegistry)
//
// The contract is designed for production from the start; implementations
// scale up without contract changes: a PoC implementation is a durable
// hash-chained file log (tamper-evident, no proofs); a CT-style Merkle
// implementation additionally provides the Prover capability for
// inclusion/consistency proofs without log replay.
package tlog

import (
	"context"
	"errors"
	"time"
)

// ErrUnsignedLog is the CONTRACT-LEVEL condition "this log cannot produce
// the signed commitment Checkpoint requires" (no signing capability was
// armed). Implementations wrap it in their own typed errors so a caller
// holding only the tlog.Log interface can detect the condition with
// errors.Is — two lookalike per-package sentinels would be silent false
// negatives across implementations.
var ErrUnsignedLog = errors.New("tlog: log has no checkpoint signer")

// Record is one immutable log entry.
type Record struct {
	// Index is the zero-based position in the log.
	Index uint64
	// Payload is the opaque record content; consumers define the encoding.
	Payload []byte
	// Hash is an implementation-defined commitment to this record: the chain
	// hash — sha256 over ( []byte(previous record's Hash, as hex text) ‖ the
	// opaque payload bytes ), the genesis record chaining from the EMPTY
	// STRING (not 32 zero bytes; pinned byte-exactly by the log contract
	// suite's vector) — for hash-chain logs, or the Merkle leaf hash for
	// tree logs. Any retroactive modification breaks every subsequent
	// commitment.
	Hash string
}

// Checkpoint is a signed commitment to the log state at Size records. The
// operator's signature makes the log head non-repudiable: having published a
// checkpoint, the operator cannot later present a different history below
// that size without detection.
type Checkpoint struct {
	// Origin identifies WHICH log this commitment is scoped to (the log ID
	// the operator armed at signing — transparency.dev vocabulary). Two
	// checkpoints are comparable (consistency-provable) only within one
	// origin. It rides the signed view (wire key "logId"), so it is
	// non-repudiable alongside Size and Head. Checkpoints serialized before
	// this field existed deserialize with an empty Origin: SignedView
	// refuses those (fail closed) rather than reconstructing a view with a
	// blank log ID — reconstructing a legacy view needs its historical log
	// ID supplied out of band.
	Origin string
	Size   uint64
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

// InclusionProof is evidence that a single record is committed by a signed
// Checkpoint — a Merkle audit path from the record's leaf to the tree root
// (RFC 6962 §2.1.1). It is self-describing: LeafIndex and TreeSize pin which
// leaf, in which tree state, the Path attests to. Proofs are a tree-log
// capability (see Prover); hash-chain logs omit Prover and are audited by
// chain replay instead.
type InclusionProof struct {
	// LeafIndex is the zero-based position of the proven record.
	LeafIndex uint64
	// TreeSize is the tree size the proof is against (== Checkpoint.Size).
	TreeSize uint64
	// Path is the ordered list of sibling hashes from leaf to root.
	Path [][]byte
}

// ConsistencyProof is evidence that the log state committed by an older
// Checkpoint is a prefix of the state committed by a newer one — the
// append-only guarantee (RFC 6962 §2.1.2).
type ConsistencyProof struct {
	OldSize uint64
	NewSize uint64
	// Path is the ordered list of node hashes bridging the two tree states.
	Path [][]byte
}

// Prover is the optional capability of proof-supporting implementations
// (CT-style Merkle logs). Callers discover it by type assertion on a Log;
// hash-chain implementations may omit it, in which case auditors verify by
// replaying the chain segment instead.
//
// Proofs are generated here but verified independently of any Log instance:
// standalone VerifyInclusion / VerifyConsistency functions — pure over the
// pinned Merkle tree-hashing scheme — land with the Merkle implementation, when
// that scheme is fixed. Keeping verification standalone is what makes a proof
// "independently verifiable": a third party checks it against a signed
// Checkpoint without trusting the log.
type Prover interface {
	// ProveInclusion returns an InclusionProof that the record at index is
	// committed by cp.
	ProveInclusion(ctx context.Context, index uint64, cp *Checkpoint) (*InclusionProof, error)
	// ProveConsistency returns a ConsistencyProof that the state committed by
	// older is a prefix of the state committed by newer (append-only evidence).
	ProveConsistency(ctx context.Context, older, newer *Checkpoint) (*ConsistencyProof, error)
}
