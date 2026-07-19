package auditor

import (
	"context"
	"errors"
	"fmt"

	"github.com/provin-line/oss/vc"
)

// ReceiptWriter is the receipt-store seam EvidenceService.Register needs:
// recording the consumed-set receipt (and the registering caller's DID) for
// a head (first-write-wins — see ReceiptStore.Put's contract). Any
// ReceiptStore satisfies it.
type ReceiptWriter interface {
	Put(headHash string, registrantDID string, consumedHashes []string) error
}

// Registrar is the audit-queue seam EvidenceService.Register needs:
// enqueueing a head for the async audit runner. Any AuditQueue satisfies it.
type Registrar interface {
	Add(headHash string) error
}

// ErrHeadNotAdmitted is returned by EvidenceService.Register when
// headVariantID has not (yet) been admitted into the local VC store — the
// arbitrary-hash amplification guard (D1): without it, a caller could enqueue
// an audit and a receipt for content this node never received. The handler
// maps it to connect.CodeFailedPrecondition.
var ErrHeadNotAdmitted = errors.New("auditor: head is not admitted in the local VC store")

// EvidenceService is the write half of the audit evidence substrate (D1,
// composite RegisterEvidence RPC): given the WIRE VARIANT id of an ADMITTED
// head (the exact signed bytes StoreVC returned as StoreVCResult.WireVariantID
// — see vc.WireVariantID's doc for what that id names and why it, not a body
// address, is what a registering caller actually holds) and the source
// content addresses it consumed, Register proves admission, resolves the
// head's BODY address, and atomically records the consumed-set receipt and
// enqueues the head for the async audit runner — the load-bearing
// resolve→receipt→queue ordering a two-RPC shape cannot give (a crash between
// two independent RPCs would leave partial evidence: a queued head with no
// receipt, or vice versa).
//
// The variant is used ONLY at admission — to prove the exact bytes a
// registering caller is vouching for are what this node actually holds — and
// is NOT itself persisted: receipts.Put and queue.Add are keyed by the head's
// BODY address, parity with the in-process aggregate emission path
// (cmd/standalone's emissionRegistrar) and the audit Runner, both of which
// already key every read/write by body address. This is a KNOWN, ACCEPTED gap
// (the pre-existing verdict/variant partition trap, P0-1 slices B/C): a
// verdict names the body it audited, not which variant proved admission for
// THIS registration, so two registrations of the same body via two different
// (but both valid) variants are indistinguishable in the recorded evidence.
// Closing it means teaching the receipt store and audit queue to carry a
// variant identity too, which neither can yet (P0-1 slices B/C).
type EvidenceService struct {
	receipts ReceiptWriter
	queue    Registrar
	// admitted proves headVariantID names bytes this node actually admitted
	// and returns the body address those bytes decode to — satisfied by
	// vcresolver.Service.ResolveVariantBody (see its doc for how it locates a
	// body from a variant id alone, and why ResolveVariant's own
	// (bodyAddress, wireVariantID) signature cannot serve this directly: a
	// registering caller here never carries a body address to pair with the
	// variant it holds).
	admitted func(ctx context.Context, headVariantID string) (bodyAddress string, ok bool, err error)
}

// NewEvidenceService returns an EvidenceService over receipts and queue,
// gated by admitted — the local-store presence check + body-address
// resolution for headVariantID (StoreVC must have admitted it first).
// admitted distinguishes a definitive "not held" (ok=false, err=nil) from a
// check FAILURE (any non-nil error, e.g. a damaged/unavailable store), which
// Register surfaces distinctly rather than laundering into ErrHeadNotAdmitted.
func NewEvidenceService(receipts ReceiptWriter, queue Registrar, admitted func(ctx context.Context, headVariantID string) (bodyAddress string, ok bool, err error)) *EvidenceService {
	return &EvidenceService{receipts: receipts, queue: queue, admitted: admitted}
}

// Register validates/canonicalizes, resolves admission, writes the receipt,
// and enqueues the head for audit — STRICTLY in that order:
//
//  1. Validate/canonicalize: a headVariantID that is not a well-formed wire
//     variant id (vc.IsWireVariantID), or a consumed set that
//     CanonicalizeConsumedSet rejects (empty, or containing a member that is
//     not a well-formed sha256:<hex> content address), is ErrInvalidArgument.
//     Neither store nor the admission check runs. This is what keeps an
//     authorized caller from pinning an irreversible first-write-wins receipt
//     with a malformed member — every reader downstream (GetConsumedSources,
//     the source-commitment auditor) would otherwise treat it as damage.
//  2. Admission: headVariantID must already be admitted in the local VC
//     store, else ErrHeadNotAdmitted (the arbitrary-hash amplification
//     guard). admitted also returns the BODY address those exact bytes
//     decode to — everything from here on keys by that, never by the variant
//     id (see the type doc's note on the variant/verdict partition trap). An
//     admission-check FAILURE (as opposed to a definitive "not admitted")
//     surfaces as its own error, never laundered into ErrHeadNotAdmitted.
//  3. receipts.Put: first-write-wins (see ReceiptStore.Put), recording
//     registrantDID — the wireauth-proven DID of the caller registering this
//     evidence — alongside the consumed set as an AUDIT-TRAIL fact. A
//     conflict (ErrReceiptConflict) is terminal — the queue is NOT touched.
//     An identical replay is an idempotent no-op (nil error, registrantDID
//     NOT overwritten even if this call's differs from what was first
//     recorded) and falls through to step 4, same as a first-time write.
//     Register never validates registrantDID against anything about the
//     head itself (e.g. the credential's own issuer) — recording it is not
//     an ownership check; binding it to head ownership is a later contract
//     stage.
//  4. queue.Add: reached only once the receipt is durably recorded (or an
//     identical replay confirmed it already was), so a queued head always has
//     SOME receipt behind it. AuditQueue.Add is itself idempotent (a re-add
//     preserves the existing attempt count), so re-registering an
//     already-queued head on replay is safe.
func (s *EvidenceService) Register(ctx context.Context, headVariantID string, consumed []string, registrantDID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !vc.IsWireVariantID(headVariantID) {
		return fmt.Errorf("%w: head_variant_address %q is not a wire variant id", ErrInvalidArgument, headVariantID)
	}
	canonical, err := CanonicalizeConsumedSet(consumed)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	bodyAddress, ok, err := s.admitted(ctx, headVariantID)
	if err != nil {
		return fmt.Errorf("auditor: check admission for %q: %w", headVariantID, err)
	}
	if !ok {
		return fmt.Errorf("%w: %q", ErrHeadNotAdmitted, headVariantID)
	}
	if err := s.receipts.Put(bodyAddress, registrantDID, canonical); err != nil {
		return fmt.Errorf("auditor: register evidence for %q: %w", bodyAddress, err)
	}
	if err := s.queue.Add(bodyAddress); err != nil {
		return fmt.Errorf("auditor: enqueue %q for audit: %w", bodyAddress, err)
	}
	return nil
}
