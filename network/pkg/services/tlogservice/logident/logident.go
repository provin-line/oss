// Package logident implements the log-identity predicate (tlog custody spec
// D-T3): the single fail-closed definition of what a tlog log id means and
// who signs it. Three log kinds share one grammar:
//
//   - emission:     log_id IS the pipeline DID the producing loop emits
//     under (config.go's PipelineDID(signer's process DID) == output
//     subject invariant makes the pipeline DID, not the process DID, the
//     log identity).
//   - sink-receipt: log_id is "sink-receipt:" + <process DID>, the receipt
//     issuer's process DID.
//   - sink-reject:  log_id is "sink-reject:" + <process DID>, the same
//     receipt-issuer process DID an archival sink's reject log rides on.
//
// Kind and OwnerDID classify a log id; SignerBase extracts the base DID from
// a checkpoint's SignedBy (a DID-URL verification method). Both parsing
// paths share one internal classifier (classify) so Kind and OwnerDID can
// never disagree about the same id.
//
// AncestorPipeline (ancestry.go) is a separate seam: it answers "which
// pipeline issued this process DID", the check an emission log's writer
// binding needs. This package defines the interface and a concrete adapter;
// the composite writer-binding predicate that combines Kind + OwnerDID +
// SignerBase + AncestorPipeline is out of this package's scope.
package logident

import (
	"errors"
	"fmt"
	"strings"

	"github.com/provin-line/oss/did/dplaax"
)

// LogKind is one of the three log identity shapes D-T3 defines.
type LogKind string

const (
	// KindEmission is a producing loop's durable log, keyed by the pipeline
	// DID it emits under.
	KindEmission LogKind = "emission"
	// KindSinkReceipt is a sink loop's receipt log, keyed by
	// "sink-receipt:" + the receipt issuer's process DID.
	KindSinkReceipt LogKind = "sink-receipt"
	// KindSinkReject is an archival sink's reject log, keyed by
	// "sink-reject:" + the same receipt issuer's process DID.
	KindSinkReject LogKind = "sink-reject"
)

const (
	sinkReceiptPrefix = "sink-receipt:"
	sinkRejectPrefix  = "sink-reject:"
)

// ErrInvalidLogID is returned for any log id Kind/OwnerDID cannot classify:
// empty, an unknown prefix, or a malformed/wrong-kind DID at a position
// where one is required. Fail-closed — there is no "unknown but tolerated"
// kind.
var ErrInvalidLogID = errors.New("logident: invalid log id")

// ErrInvalidSignedBy is returned by SignerBase for empty input, a
// fragmentless value, or a base that does not parse as a valid did:dplaax
// identifier.
var ErrInvalidSignedBy = errors.New("logident: invalid signed-by")

// Kind classifies logID into one of the three known shapes. It fails closed
// on anything else: empty, an unrecognized prefix, or a DID that is
// malformed, uses an unsupported method/account type, or is the wrong DID
// kind for its position (an emission id must be a pipeline DID; a
// sink-receipt/sink-reject suffix must be a process DID).
func Kind(logID string) (LogKind, error) {
	kind, _, err := classify(logID)
	return kind, err
}

// OwnerDID returns the DID that owns logID: for an emission log id, the id
// itself (already a DID); for sink-receipt/sink-reject, the validated
// process-DID suffix after the prefix. Fail-closed on the same shapes Kind
// rejects.
func OwnerDID(logID string) (string, error) {
	_, owner, err := classify(logID)
	return owner, err
}

// classify is the single parse Kind and OwnerDID both read, so the two can
// never classify the same id differently (D-T3: "one definition, no
// per-handler variants").
func classify(logID string) (LogKind, string, error) {
	if logID == "" {
		return "", "", fmt.Errorf("%w: empty log id", ErrInvalidLogID)
	}
	if suffix, ok := strings.CutPrefix(logID, sinkReceiptPrefix); ok {
		if _, err := parseProcessDID(suffix); err != nil {
			return "", "", fmt.Errorf("%w: sink-receipt suffix %q: %v", ErrInvalidLogID, suffix, err)
		}
		return KindSinkReceipt, suffix, nil
	}
	if suffix, ok := strings.CutPrefix(logID, sinkRejectPrefix); ok {
		if _, err := parseProcessDID(suffix); err != nil {
			return "", "", fmt.Errorf("%w: sink-reject suffix %q: %v", ErrInvalidLogID, suffix, err)
		}
		return KindSinkReject, suffix, nil
	}
	if _, err := parsePipelineDID(logID); err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrInvalidLogID, err)
	}
	return KindEmission, logID, nil
}

// parsePipelineDID parses and semantically validates s, requiring it name a
// pipeline (the emission log id shape).
func parsePipelineDID(s string) (*dplaax.DID, error) {
	d, err := parseValidDID(s)
	if err != nil {
		return nil, err
	}
	if !d.IsPipeline() {
		return nil, fmt.Errorf("%q is not a pipeline DID", s)
	}
	return d, nil
}

// parseProcessDID parses and semantically validates s, requiring it name a
// process (the sink-receipt/sink-reject suffix shape).
func parseProcessDID(s string) (*dplaax.DID, error) {
	d, err := parseValidDID(s)
	if err != nil {
		return nil, err
	}
	if !d.IsProcess() {
		return nil, fmt.Errorf("%q is not a process DID", s)
	}
	return d, nil
}

// parseValidDID parses s as a did:dplaax identifier and applies the
// deployment's semantic validation (supported account type, registry shape,
// known resource pattern) — the same gate every other DID-consuming
// boundary in this codebase applies before trusting a DID string.
func parseValidDID(s string) (*dplaax.DID, error) {
	d, err := dplaax.Parse(s)
	if err != nil {
		return nil, err
	}
	if err := dplaax.ValidateDID(d); err != nil {
		return nil, err
	}
	return d, nil
}

// SignerBase extracts the base DID from signedBy, a checkpoint's SignedBy
// field — a DID-URL verification method (e.g. "did:dplaax:...#signing").
//
// Fail-closed decision (documented per the task brief): a fragmentless
// value is REJECTED, not accepted as its own base. This mirrors every other
// verification-method base-DID split in this codebase — didregistry's
// verifyDocProof, delegation.Verify, and vc.Verifier all compute
// strings.Cut(vm, "#") and treat found=false as invalid input, never as an
// implicit "the whole string is the base". A checkpoint's SignedBy is
// documented (tlog.CheckpointSigner) as a verification method, i.e. always
// DID-URL shaped; a fragmentless value is therefore a malformed signer
// identity, not a legitimate bare-DID signer.
func SignerBase(signedBy string) (string, error) {
	base, _, found := strings.Cut(signedBy, "#")
	if !found || base == "" {
		return "", fmt.Errorf("%w: %q carries no verification-method fragment", ErrInvalidSignedBy, signedBy)
	}
	if _, err := parseValidDID(base); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidSignedBy, err)
	}
	return base, nil
}
