package tlog

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/provin-line/oss/tlog/internal/rfc6962"
)

// The standalone proof verifiers below are pure over the pinned tree-log
// scheme (RFC 6962 over SHA-256, lowercase-hex heads): a third party checks
// a proof against a signed Checkpoint without trusting — or reaching — the
// log. Signature verification is deliberately separate: reconstruct the
// bytes with Checkpoint.SignedView and check them with a crypto.Verifier.
//
// Malformed proofs are REJECTED, not undefined, so independent
// implementations cannot disagree over edge cases: nil inputs, non-32-byte
// path elements, malformed head hex, index/size violations, size mismatches
// between proof and checkpoint, and surplus or insufficient path nodes are
// all errors.

// VerifyInclusion checks that payload is committed at proof.LeafIndex by cp
// (RFC 6962 §2.1.1 / RFC 9162 §2.1.3.2).
func VerifyInclusion(cp *Checkpoint, proof *InclusionProof, payload []byte) error {
	if cp == nil || proof == nil {
		return errors.New("tlog: verify inclusion: nil checkpoint or proof")
	}
	if proof.TreeSize != cp.Size {
		return fmt.Errorf("tlog: verify inclusion: proof tree size %d != checkpoint size %d", proof.TreeSize, cp.Size)
	}
	root, err := parseHead(cp.Head)
	if err != nil {
		return fmt.Errorf("tlog: verify inclusion: %w", err)
	}
	path, err := parsePath(proof.Path)
	if err != nil {
		return fmt.Errorf("tlog: verify inclusion: %w", err)
	}
	got, err := rfc6962.RootFromInclusion(rfc6962.LeafHash(payload), proof.LeafIndex, proof.TreeSize, path)
	if err != nil {
		return fmt.Errorf("tlog: verify inclusion: %w", err)
	}
	if got != root {
		return errors.New("tlog: verify inclusion: recomputed root does not match the checkpoint head")
	}
	return nil
}

// VerifyConsistency checks that the log state committed by older is a
// prefix of the state committed by newer (RFC 6962 §2.1.2 / RFC 9162
// §2.1.4.2). The two checkpoints MUST carry the same non-empty Origin —
// checkpoints of different logs are not comparable, and that misuse is
// rejected rather than left undefined. Degenerate forms: equal sizes
// require equal heads and an empty path; an older size of zero is a vacuous
// prefix and requires an empty path.
func VerifyConsistency(older, newer *Checkpoint, proof *ConsistencyProof) error {
	if older == nil || newer == nil || proof == nil {
		return errors.New("tlog: verify consistency: nil checkpoint or proof")
	}
	if older.Origin == "" || newer.Origin == "" {
		return errors.New("tlog: verify consistency: checkpoint carries no origin")
	}
	if older.Origin != newer.Origin {
		return fmt.Errorf("tlog: verify consistency: origins differ (%q vs %q) — checkpoints of different logs are not comparable", older.Origin, newer.Origin)
	}
	if proof.OldSize != older.Size || proof.NewSize != newer.Size {
		return fmt.Errorf("tlog: verify consistency: proof sizes (%d, %d) != checkpoint sizes (%d, %d)", proof.OldSize, proof.NewSize, older.Size, newer.Size)
	}
	if older.Size > newer.Size {
		return fmt.Errorf("tlog: verify consistency: older size %d exceeds newer size %d", older.Size, newer.Size)
	}
	if older.Size == newer.Size {
		if older.Head != newer.Head {
			return errors.New("tlog: verify consistency: equal sizes with different heads")
		}
		if len(proof.Path) != 0 {
			return errors.New("tlog: verify consistency: equal sizes admit only an empty path")
		}
		return nil
	}
	if older.Size == 0 {
		if len(proof.Path) != 0 {
			return errors.New("tlog: verify consistency: an empty older state admits only an empty path (vacuous prefix)")
		}
		return nil
	}
	oldRoot, err := parseHead(older.Head)
	if err != nil {
		return fmt.Errorf("tlog: verify consistency: older head: %w", err)
	}
	newRoot, err := parseHead(newer.Head)
	if err != nil {
		return fmt.Errorf("tlog: verify consistency: newer head: %w", err)
	}
	path, err := parsePath(proof.Path)
	if err != nil {
		return fmt.Errorf("tlog: verify consistency: %w", err)
	}
	fr, sr, err := rfc6962.RootsFromConsistency(older.Size, newer.Size, oldRoot, path)
	if err != nil {
		return fmt.Errorf("tlog: verify consistency: %w", err)
	}
	if fr != oldRoot {
		return errors.New("tlog: verify consistency: recomputed older root does not match the older checkpoint")
	}
	if sr != newRoot {
		return errors.New("tlog: verify consistency: recomputed newer root does not match the newer checkpoint")
	}
	return nil
}

func parseHead(head string) ([rfc6962.HashSize]byte, error) {
	var out [rfc6962.HashSize]byte
	b, err := hex.DecodeString(head)
	if err != nil {
		return out, fmt.Errorf("malformed head %q: %w", head, err)
	}
	if len(b) != rfc6962.HashSize {
		return out, fmt.Errorf("head is %d bytes, want %d", len(b), rfc6962.HashSize)
	}
	copy(out[:], b)
	return out, nil
}

func parsePath(path [][]byte) ([][rfc6962.HashSize]byte, error) {
	out := make([][rfc6962.HashSize]byte, len(path))
	for i, p := range path {
		if len(p) != rfc6962.HashSize {
			return nil, fmt.Errorf("path element %d is %d bytes, want %d", i, len(p), rfc6962.HashSize)
		}
		copy(out[i][:], p)
	}
	return out, nil
}
