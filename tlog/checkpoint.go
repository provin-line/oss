package tlog

import (
	"errors"
	"strconv"
	"time"

	"github.com/provin-line/oss/canon/jcs"
	"github.com/provin-line/oss/crypto"
)

// checkpointPurpose domain-separates checkpoint signatures from every other
// signature the operator's key produces.
const checkpointPurpose = "dplaax-tlog-checkpoint"

// CheckpointSigner arms a log implementation to produce signed Checkpoints.
// The arming is implementation-independent — any tlog.Log that signs
// checkpoints takes the same five values — which is why it lives with the
// contract, not with one implementation.
type CheckpointSigner struct {
	Signer    crypto.Signer
	SignerDID string
	KeyID     string
	// VerificationMethod is the DID URL published as Checkpoint.SignedBy.
	VerificationMethod string
	// LogID is the log identity published as Checkpoint.Origin and bound
	// into the signed view.
	LogID string
}

// SignedView returns the exact byte sequence a checkpoint signature covers:
// the JCS-canonical view {v:1, purpose:"dplaax-tlog-checkpoint",
// logId:Origin, head, signedBy, size (decimal string), timestamp (RFC 3339,
// as stamped — the view does NOT normalize to UTC; signers SHOULD stamp
// UTC)}. Signer implementations sign this and verifiers reconstruct it, so
// the two sides can never disagree about the view (single implementation of
// the byte contract).
//
// Fail-closed: a nil checkpoint, an empty Origin (a legacy checkpoint
// serialized before Origin existed), or an empty SignedBy is an error —
// never a view with blank identity fields.
func (cp *Checkpoint) SignedView() ([]byte, error) {
	if cp == nil {
		return nil, errors.New("tlog: signed view of a nil checkpoint")
	}
	if cp.Origin == "" {
		return nil, errors.New("tlog: checkpoint carries no origin — a legacy checkpoint's view needs its historical log ID supplied out of band")
	}
	if cp.SignedBy == "" {
		return nil, errors.New("tlog: checkpoint carries no signer identity")
	}
	return jcs.Canonicalize(map[string]any{
		"v":         1,
		"purpose":   checkpointPurpose,
		"logId":     cp.Origin,
		"head":      cp.Head,
		"signedBy":  cp.SignedBy,
		"size":      strconv.FormatUint(cp.Size, 10),
		"timestamp": cp.Timestamp.Format(time.RFC3339),
	})
}

// SignCheckpoint builds and signs a Checkpoint over (size, head) at ts with
// signer — the one production path from log state to signed commitment,
// shared by the log implementations so arming and view semantics cannot
// drift between them.
func SignCheckpoint(size uint64, head string, signer *CheckpointSigner, ts time.Time) (*Checkpoint, error) {
	if signer == nil {
		return nil, errors.New("tlog: sign checkpoint: nil signer")
	}
	cp := &Checkpoint{
		Origin:    signer.LogID,
		Size:      size,
		Head:      head,
		Timestamp: ts,
		SignedBy:  signer.VerificationMethod,
	}
	view, err := cp.SignedView()
	if err != nil {
		return nil, err
	}
	sig, err := signer.Signer.Sign(signer.SignerDID, signer.KeyID, view)
	if err != nil {
		return nil, err
	}
	cp.Signature = sig
	return cp, nil
}
