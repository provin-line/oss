package auditor

import (
	"context"
	"errors"
	"fmt"
)

// ReceiptWriter is the receipt-store seam EvidenceService.Register needs:
// recording the consumed-set receipt for a head (first-write-wins — see
// ReceiptStore.Put's contract). Any ReceiptStore satisfies it.
type ReceiptWriter interface {
	Put(headHash string, consumedHashes []string) error
}

// Registrar is the audit-queue seam EvidenceService.Register needs:
// enqueueing a head for the async audit runner. Any AuditQueue satisfies it.
type Registrar interface {
	Add(headHash string) error
}

// ErrHeadNotAdmitted is returned by EvidenceService.Register when
// headVariantAddr has not (yet) been admitted into the local VC store — the
// arbitrary-hash amplification guard (D1): without it, a caller could enqueue
// an audit and a receipt for content this node never received. The handler
// maps it to connect.CodeFailedPrecondition.
var ErrHeadNotAdmitted = errors.New("auditor: head is not admitted in the local VC store")

// EvidenceService is the write half of the audit evidence substrate (D1,
// composite RegisterEvidence RPC): given the content address of an ADMITTED
// head and the source content addresses it consumed, Register atomically
// records the consumed-set receipt and enqueues the head for the async audit
// runner — the load-bearing store→receipt→queue ordering a two-RPC shape
// cannot give (a crash between two independent RPCs would leave partial
// evidence: a queued head with no receipt, or vice versa).
type EvidenceService struct {
	receipts ReceiptWriter
	queue    Registrar
	admitted func(ctx context.Context, variantAddr string) (bool, error)
}

// NewEvidenceService returns an EvidenceService over receipts and queue,
// gated by admitted — the local-store presence check for headVariantAddr
// (StoreVC must have admitted it first). admitted distinguishes a definitive
// "not held" (false, nil) from a check FAILURE (any non-nil error, e.g. a
// damaged/unavailable store), which Register surfaces distinctly rather than
// laundering into ErrHeadNotAdmitted.
func NewEvidenceService(receipts ReceiptWriter, queue Registrar, admitted func(ctx context.Context, variantAddr string) (bool, error)) *EvidenceService {
	return &EvidenceService{receipts: receipts, queue: queue, admitted: admitted}
}

// Register validates/canonicalizes, checks admission, writes the receipt, and
// enqueues the head for audit — STRICTLY in that order:
//
//  1. Validate/canonicalize: a malformed head address, or a consumed set that
//     CanonicalizeConsumedSet rejects (empty, or containing a member that is
//     not a well-formed sha256:<hex> content address), is ErrInvalidArgument.
//     Neither store nor the admission check runs. This is what keeps an
//     authorized caller from pinning an irreversible first-write-wins receipt
//     with a malformed member — every reader downstream (GetConsumedSources,
//     the source-commitment auditor) would otherwise treat it as damage.
//  2. Admission: headVariantAddr must already be admitted in the local VC
//     store, else ErrHeadNotAdmitted (the arbitrary-hash amplification guard).
//     An admission-check FAILURE (as opposed to a definitive "not admitted")
//     surfaces as its own error, never laundered into ErrHeadNotAdmitted.
//  3. receipts.Put: first-write-wins (see ReceiptStore.Put). A conflict
//     (ErrReceiptConflict) is terminal — the queue is NOT touched. An
//     identical replay is an idempotent no-op (nil error) and falls through
//     to step 4, same as a first-time write.
//  4. queue.Add: reached only once the receipt is durably recorded (or an
//     identical replay confirmed it already was), so a queued head always has
//     SOME receipt behind it. AuditQueue.Add is itself idempotent (a re-add
//     preserves the existing attempt count), so re-registering an
//     already-queued head on replay is safe.
func (s *EvidenceService) Register(ctx context.Context, headVariantAddr string, consumed []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !isContentAddress(headVariantAddr) {
		return fmt.Errorf("%w: head_variant_address %q is not a sha256:<hex> content address", ErrInvalidArgument, headVariantAddr)
	}
	canonical, err := CanonicalizeConsumedSet(consumed)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	ok, err := s.admitted(ctx, headVariantAddr)
	if err != nil {
		return fmt.Errorf("auditor: check admission for %q: %w", headVariantAddr, err)
	}
	if !ok {
		return fmt.Errorf("%w: %q", ErrHeadNotAdmitted, headVariantAddr)
	}
	if err := s.receipts.Put(headVariantAddr, canonical); err != nil {
		return fmt.Errorf("auditor: register evidence for %q: %w", headVariantAddr, err)
	}
	if err := s.queue.Add(headVariantAddr); err != nil {
		return fmt.Errorf("auditor: enqueue %q for audit: %w", headVariantAddr, err)
	}
	return nil
}
