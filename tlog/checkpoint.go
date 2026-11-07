package tlog

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
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
// logId:Origin, head, signedBy, size (decimal string), timestamp (RFC 3339 in
// UTC, to the second)}. Signer implementations sign this and verifiers
// reconstruct it, so the two sides can never disagree about the view (single
// implementation of the byte contract).
//
// Each value has one spelling, and a value in another is refused, never
// re-spelled: the head is in lower case, and the timestamp is in UTC (offset
// zero), whole seconds, and within the years RFC 3339 writes, so its RFC 3339
// form reads back as the same instant. The wire carries the timestamp in UTC
// as well.
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
	// One root and one instant each have one spelling: a head in another
	// case would get its own signature and its own verdicts, and a timestamp
	// the view writes differently from its value would share a signature with
	// another instant, or be signed in a form the wire does not carry.
	if !lowerCaseHead(cp.Head) {
		return nil, fmt.Errorf("tlog: checkpoint head %q is not in lower case", cp.Head)
	}
	if err := viewTimestamp(cp.Timestamp); err != nil {
		return nil, err
	}
	return jcs.CanonicalizeRFC8785(map[string]any{
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

// lowerCaseHead reports whether head has no upper-case ASCII letter: a head
// (a hex hash) has one spelling, the lower-case one the logs write.
// viewTimestamp refuses a timestamp the signed view would not write as its
// one spelling: not in UTC, or with an RFC 3339 form that does not read back
// as the same instant (a fraction of a second, a year outside 0000–9999).
func viewTimestamp(ts time.Time) error {
	if _, offset := ts.Zone(); offset != 0 {
		return fmt.Errorf("tlog: checkpoint timestamp %s is not in UTC", ts.Format(time.RFC3339Nano))
	}
	back, err := time.Parse(time.RFC3339, ts.Format(time.RFC3339))
	if err != nil || !back.Equal(ts) {
		return fmt.Errorf("tlog: checkpoint timestamp %s is not one the signed view writes exactly (whole seconds, years 0000–9999)", ts.Format(time.RFC3339Nano))
	}
	return nil
}

func lowerCaseHead(head string) bool {
	return strings.IndexFunc(head, func(r rune) bool { return 'A' <= r && r <= 'Z' }) < 0
}
