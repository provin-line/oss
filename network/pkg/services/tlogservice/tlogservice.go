// Package tlogservice is the read service behind dplaax.tlog.v1.TlogService:
// a registry of the node's per-loop emission logs (keyed by log id = the
// producing loop's output subject), serving signed checkpoints and record
// ranges for transport-loss reconciliation. It owns the domain logic
// (registry lookup, range bounds); the logs are the tlog implementations
// and the handler is pure proto↔domain conversion.
package tlogservice

import (
	"context"
	"errors"
	"fmt"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/network/pkg/didresolver"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
	"github.com/provin-line/oss/network/pkg/services/tlogservice/logident"
	"github.com/provin-line/oss/network/pkg/services/tlogservice/mirrorstore"
	"github.com/provin-line/oss/tlog"
)

// Sentinel errors the handler maps to Connect codes (errors.Is, never
// string matching).
var (
	// ErrNotFound is a log id no producing loop on this node owns, and (once
	// a mirror store is wired) no mirror has ever heard of either.
	ErrNotFound = errors.New("tlogservice: no emission log with that id")
	// ErrInvalidArgument is a malformed range parameter, an unparseable log
	// id, or a structurally invalid MirrorLogSegment request (nil
	// checkpoint, checkpoint.size misaligned, or a from_index/len overflow).
	ErrInvalidArgument = errors.New("tlogservice: invalid argument")
	// ErrMirrorNotConfigured is MirrorSegment/MirrorState's error when this
	// Service was built with a nil MirrorConfig (New's mirror param) — this
	// node never wired a mirror store, mirroring
	// chainmanager/handler.OperatorHandler's "not wired" posture for an
	// optional RPC dependency (CodeUnimplemented at the handler).
	ErrMirrorNotConfigured = errors.New("tlogservice: this node has no mirror store configured")
	// ErrIdentityMismatch is MirrorSegment's D-T3 identity-enforcement
	// failure: an invalid/unverifiable checkpoint signature, a
	// wireauth-proven caller that does not equal the checkpoint's
	// SignerBase, a process whose pipeline ancestor does not match the log
	// owner, or a signer that conflicts with the log's already-pinned
	// signer. One sentinel for the whole D-T3 bucket — every sub-case maps
	// to the same connect code (PermissionDenied).
	ErrIdentityMismatch = errors.New("tlogservice: mirror segment: caller identity does not satisfy the log's writer binding")
	// ErrCapExceeded is MirrorSegment's D-T2 rule 5 cap failure: the batch's
	// record count or summed byte length exceeds the configured maximum.
	ErrCapExceeded = errors.New("tlogservice: mirror segment: batch exceeds the configured cap")
	// ErrMirrorConflict is MirrorSegment's D-T2 rule 1/2 failure that is NOT
	// a malformed-request error: a gap ahead of the acked size, a partial
	// overlap with already-mirrored records (a replay whose payloads do not
	// byte-match what is already stored), or a recomputed chain head that
	// does not equal the checkpoint's head.
	ErrMirrorConflict = errors.New("tlogservice: mirror segment: segment does not align with the mirrored log")
)

// MirrorStore is the consumer-side view of mirrorstore.Store this Service
// depends on for its D-T2/D-T4 mirror-custody surface (dependency inverted,
// narrowest interface for what MirrorSegment/MirrorState/Checkpoint/Records
// actually call). *mirrorstore.Store satisfies it structurally.
//
// AppendSegment (not the older AppendVerified) is what MirrorSegment calls:
// it resolves from_index against the live acked size — replay vs. gap vs.
// overlap vs. exact-extend — atomically under the store's own lock, so a
// concurrent identical retry can never read a torn intermediate size and
// fail the exact-extend arithmetic (which would surface as Internal instead
// of the required replay no-op success).
type MirrorStore interface {
	AckedSize(logID string) (uint64, error)
	Checkpoint(logID string) (*tlog.Checkpoint, error)
	Get(logID string, index uint64) (*tlog.Record, error)
	AppendSegment(logID string, fromIndex uint64, records [][]byte, cp *tlog.Checkpoint) (uint64, error)
}

// DIDResolver resolves a DID to its document — the read view MirrorSegment
// needs to verify a checkpoint's OWN signature (D-T3), independent of
// whichever resolver already checked the wireauth proof itself. Same method
// shape as wireauth.DIDResolver on purpose: the composition root passes the
// SAME concrete resolver instance to both (*didresolver.Resolver satisfies
// this interface directly).
type DIDResolver interface {
	Resolve(ctx context.Context, did string) (*did.DIDDocument, error)
}

// MirrorConfig bundles the D-T4 mirror store and D-T3 identity-enforcement
// dependencies MirrorSegment/MirrorState need beyond the static log map. A
// nil *MirrorConfig to New keeps today's map-only behavior (cmd/standalone):
// MirrorSegment/MirrorState both return ErrMirrorNotConfigured rather than
// touching dependencies this node was never given.
type MirrorConfig struct {
	// Store is the durable mirror (mirrorstore.Store).
	Store MirrorStore
	// DIDResolver resolves a checkpoint's SignedBy DID to verify its
	// signature — reuse the SAME resolver the node's other wireauth-checked
	// RPCs use.
	DIDResolver DIDResolver
	// Ancestry answers "which pipeline issued this process DID" for an
	// emission log's writer binding (D-T3).
	Ancestry logident.PipelineAncestry
	// Crypto verifies a checkpoint's signature bytes against a resolved
	// public key.
	Crypto crypto.Verifier
	// MaxBatchRecords / MaxBatchBytes are the D-T2 rule 5 caps
	// (pipelineconfig.TlogMirrorConfig).
	MaxBatchRecords int
	MaxBatchBytes   int
}

// Service serves the node's emission logs: the static map of local
// producing loops, and — when mirror is non-nil — the durable mirror store
// as a SECOND source behind it (D-T4). Reads check the map first: a log
// this node still runs locally is served from its live signer, never a
// possibly-lagging mirror copy.
type Service struct {
	logs   map[string]tlog.Log
	mirror *MirrorConfig
}

// New returns a Service over the node's log registry (log id → log; the map
// is captured as-is, the node builds it once at boot) and, when mirror is
// non-nil, the D-T4 mirror-custody surface.
func New(logs map[string]tlog.Log, mirror *MirrorConfig) *Service {
	return &Service{logs: logs, mirror: mirror}
}

// Checkpoint returns the signed head commitment of the log with id logID:
// from the local map when this node runs it, else (when a mirror store is
// wired) the mirror's own persisted, remotely-signed checkpoint, else a
// wrapped ErrNotFound. A local log that cannot sign (armed without a
// checkpoint signer) surfaces its own error — a node misconfiguration, not
// absence.
func (s *Service) Checkpoint(ctx context.Context, logID string) (*tlog.Checkpoint, error) {
	if l, ok := s.logs[logID]; ok {
		cp, err := l.Checkpoint(ctx)
		if err != nil {
			return nil, fmt.Errorf("tlogservice: checkpoint %q: %w", logID, err)
		}
		// The signed Origin and the registry key must agree — a mismatch is
		// a node misconfiguration (a log armed with the wrong LogID) and
		// serving it would publish a checkpoint whose signed identity
		// contradicts the id it was requested under. Fail closed.
		if cp.Origin != logID {
			return nil, fmt.Errorf("tlogservice: checkpoint %q: signed origin %q does not match the registry key", logID, cp.Origin)
		}
		return cp, nil
	}
	if s.mirror != nil {
		if custodyOnly(logID) {
			// A mirrored sink-reject log is custodied but NEVER served through
			// TlogService reads (D-T3/D-T5: today's never-served posture —
			// operator tooling reads the mirror store directly). It stays fully
			// available to the WRITE/STATE paths (MirrorSegment / MirrorState),
			// so custody still works; only this read fallback refuses it.
			return nil, fmt.Errorf("%w: %q", ErrNotFound, logID)
		}
		cp, err := s.mirror.Store.Checkpoint(logID)
		if err != nil {
			if errors.Is(err, mirrorstore.ErrNotFound) {
				return nil, fmt.Errorf("%w: %q", ErrNotFound, logID)
			}
			return nil, fmt.Errorf("tlogservice: checkpoint %q: %w", logID, err)
		}
		// mirrorstore.AppendSegment already enforces cp.Origin == logID at
		// accept time (it is the store's own key), so no re-check is needed
		// here the way the local-log branch above needs one against an
		// arbitrarily-armed live signer.
		return cp, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrNotFound, logID)
}

// Records returns the records [start, start+count) of the log with id
// logID, index-ascending: from the local map when this node runs it, else
// (when a mirror store is wired) the mirror's own verified prefix. A start
// at or past the current size is an empty slice (a caught-up reader is a
// normal state, not an error); a range that extends past the end returns
// what exists.
func (s *Service) Records(ctx context.Context, logID string, start uint64, count int) ([]*tlog.Record, error) {
	if count <= 0 {
		return nil, fmt.Errorf("%w: count %d is not positive", ErrInvalidArgument, count)
	}
	if l, ok := s.logs[logID]; ok {
		size, err := l.Size(ctx)
		if err != nil {
			return nil, fmt.Errorf("tlogservice: size %q: %w", logID, err)
		}
		var out []*tlog.Record
		for i := start; i < size && len(out) < count; i++ {
			rec, err := l.Get(ctx, i)
			if err != nil {
				return nil, fmt.Errorf("tlogservice: record %q[%d]: %w", logID, i, err)
			}
			out = append(out, rec)
		}
		return out, nil
	}
	if s.mirror != nil {
		if custodyOnly(logID) {
			// Sink-reject logs are mirrored for custody but never served
			// through TlogService reads (see Checkpoint's identical gate).
			return nil, fmt.Errorf("%w: %q", ErrNotFound, logID)
		}
		size, err := s.mirror.Store.AckedSize(logID)
		if err != nil {
			return nil, fmt.Errorf("tlogservice: size %q: %w", logID, err)
		}
		if size == 0 {
			// AckedSize returns (0, nil) for BOTH "never mirrored" and
			// "mirrored, nothing acked yet" — indistinguishable by design
			// (mirrorstore.AckedSize's own doc). Reads NotFound either way,
			// matching the map path's NotFound for a wholly unknown id.
			return nil, fmt.Errorf("%w: %q", ErrNotFound, logID)
		}
		var out []*tlog.Record
		for i := start; i < size && len(out) < count; i++ {
			rec, err := s.mirror.Store.Get(logID, i)
			if err != nil {
				return nil, fmt.Errorf("tlogservice: record %q[%d]: %w", logID, i, err)
			}
			out = append(out, rec)
		}
		return out, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrNotFound, logID)
}

// custodyOnly reports whether logID names a log that is mirrored for custody
// but MUST NOT be served through TlogService's read RPCs (GetLogCheckpoint /
// ListLogRecords) — today only the sink-reject kind (spec D-T3/D-T5: reject
// logs are receipt-issuer-signed evidence, custodied and readable by operator
// tooling straight off the mirror store, but never exposed to a tlog:read
// principal). The WRITE/STATE paths (MirrorSegment / MirrorState / the store's
// AckedSize) do NOT consult this gate, so custody of a sink-reject log still
// works end to end. A log id logident.Kind cannot classify is not treated as
// custody-only: it simply is not a sink-reject log, and the store lookup that
// follows returns NotFound for an unknown id anyway.
func custodyOnly(logID string) bool {
	kind, err := logident.Kind(logID)
	return err == nil && kind == logident.KindSinkReject
}

// CheckBatchCaps validates a MirrorLogSegment batch's record count and summed
// byte length against the D-T2 rule 5 caps — the SINGLE cap-policy definition,
// owned by the service (the caps + the ErrCapExceeded sentinel never leave the
// domain layer). The handler calls it with the cheap structural sizes
// (len(payloads), sum of lengths) BEFORE hashing payloads or verifying the
// wireauth proof (a pre-auth DoS guard); MirrorSegment calls the SAME method as
// defense in depth, so the two can never diverge. A map-only node (no mirror
// store wired) has no caps to enforce: the check is a no-op (nil), and the
// call proceeds to whatever ErrMirrorNotConfigured path applies.
func (s *Service) CheckBatchCaps(recordCount, totalBytes int) error {
	if s.mirror == nil {
		return nil
	}
	if recordCount > s.mirror.MaxBatchRecords {
		return fmt.Errorf("%w: %d records exceeds max-batch-records %d", ErrCapExceeded, recordCount, s.mirror.MaxBatchRecords)
	}
	if totalBytes > s.mirror.MaxBatchBytes {
		return fmt.Errorf("%w: %d bytes exceeds max-batch-bytes %d", ErrCapExceeded, totalBytes, s.mirror.MaxBatchBytes)
	}
	return nil
}

// DecodeSegment unframes a MirrorLogSegment request's record_payloads_framed
// blob into the ordered payload list, bounded by this service's D-T2 caps —
// the BOUNDED pre-auth guard the handler runs before hashing payloads or
// verifying the wireauth proof. UnframeRecordPayloads enforces the count/byte
// caps DURING the scan, so a hostile blob is rejected before a [][]byte larger
// than the caps is ever materialized (unlike the old repeated-bytes field,
// which Connect decoded in full before any guard ran).
//
// A map-only node (no mirror store wired) has no caps and never custodies — it
// returns ErrMirrorNotConfigured before touching the blob, so the handler maps
// it to Unimplemented WITHOUT unframing (mirrors MirrorState's not-configured
// posture). CheckBatchCaps stays the shared cap POLICY that MirrorSegment
// re-applies to in.Records as defense in depth; DecodeSegment is the same
// policy applied at the decode boundary.
func (s *Service) DecodeSegment(framed []byte) ([][]byte, error) {
	if s.mirror == nil {
		return nil, ErrMirrorNotConfigured
	}
	return UnframeRecordPayloads(framed, s.mirror.MaxBatchRecords, s.mirror.MaxBatchBytes)
}

// MirrorState returns the registry's durable mirror size for logID — the
// shipper's resume cursor (GetMirrorState, D-T2 rule 6). logID is
// identity-parsed (logident.Kind) before touching the store: a malformed id
// is ErrInvalidArgument, never routed to a lookup that would report "0,
// nothing mirrored" for garbage input.
func (s *Service) MirrorState(logID string) (uint64, error) {
	if _, err := logident.Kind(logID); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	if s.mirror == nil {
		return 0, ErrMirrorNotConfigured
	}
	return s.mirror.Store.AckedSize(logID)
}

// MirrorSegmentInput is one MirrorLogSegment call's decoded arguments
// (proto → domain conversion happens in the handler; this is domain-only).
// CallerDID is the wireauth-proven signer DID — verified by the handler's
// Verifier BEFORE this method is ever called (D-T2 rule "wireauth covers
// the payload list"/acceptance rule 1's proof check). MirrorSegment trusts
// it as AUTHENTICATED but not yet AUTHORIZED: authorization (D-T3) is this
// method's own job.
type MirrorSegmentInput struct {
	LogID      string
	FromIndex  uint64
	Records    [][]byte
	Checkpoint *tlog.Checkpoint
	CallerDID  string
}

// MirrorSegment implements D-T2's MirrorLogSegment acceptance rules 1
// (chain-to-head + the checkpoint's own signature, D-T3), 2 (exact-extend/
// gap/overlap/replay), 4 (caps, "rule 5" in the spec's own numbering), and 6
// (store append) — rule 1's WIREAUTH half (the proof over log_id,
// from_index, checkpoint.head, segment_digest) is verified by the handler
// BEFORE this is ever called. Enforced in this exact order (task-5 brief):
//
//  1. identity (D-T3): checkpoint signature, caller-vs-signer equality,
//     per-kind ancestry/equality, first-segment signer pinning —
//     ErrIdentityMismatch (PermissionDenied).
//  2. caps (rule 5) — ErrCapExceeded (ResourceExhausted).
//  3. overflow / checkpoint.size alignment (pure, race-free) —
//     ErrInvalidArgument.
//  4. store.AppendSegment (rules 1, 2, 6): the alignment-against-live-acked
//     resolution (exact-extend / gap / partial-overlap / byte-identical
//     replay) AND the chain-to-head recompute happen INSIDE the store, under
//     the same lock the durable append holds, so a concurrent identical retry
//     can never fail on a torn intermediate size. Every "does not align"
//     outcome comes back as mirrorstore.ErrConflict → ErrMirrorConflict
//     (FailedPrecondition); monotonicity is enforced by the store.
//
// Returns the durable mirror size after the call (unchanged on a
// byte-identical replay no-op).
func (s *Service) MirrorSegment(ctx context.Context, in MirrorSegmentInput) (uint64, error) {
	if s.mirror == nil {
		return 0, ErrMirrorNotConfigured
	}
	if in.Checkpoint == nil {
		return 0, fmt.Errorf("%w: mirror segment %q: nil checkpoint", ErrInvalidArgument, in.LogID)
	}
	// The checkpoint's OWN Origin (what its signature actually covers) must
	// agree with the request's top-level log_id — a self-contradictory
	// request is a malformed argument, not an identity failure, and
	// catching it here keeps mirrorstore.AppendSegment's own Origin==logID
	// check (a plain, non-sentinel error) structurally unreachable from this
	// path.
	if in.Checkpoint.Origin != in.LogID {
		return 0, fmt.Errorf("%w: mirror segment: checkpoint.log_id %q != log_id %q", ErrInvalidArgument, in.Checkpoint.Origin, in.LogID)
	}

	kind, err := logident.Kind(in.LogID)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}

	if err := s.verifyMirrorIdentity(ctx, kind, in); err != nil {
		return 0, err
	}

	var totalBytes int
	for _, p := range in.Records {
		totalBytes += len(p)
	}
	if err := s.CheckBatchCaps(len(in.Records), totalBytes); err != nil {
		return 0, err
	}

	total := in.FromIndex + uint64(len(in.Records))
	if total < in.FromIndex {
		return 0, fmt.Errorf("%w: mirror segment %q: from_index %d + %d records overflows uint64", ErrInvalidArgument, in.LogID, in.FromIndex, len(in.Records))
	}
	if in.Checkpoint.Size != total {
		return 0, fmt.Errorf("%w: mirror segment %q: checkpoint.size %d != from_index %d + %d records", ErrInvalidArgument, in.LogID, in.Checkpoint.Size, in.FromIndex, len(in.Records))
	}

	// Alignment against the store's live acked size — the exact-extend /
	// gap / partial-overlap / byte-identical-replay resolution AND the
	// chain-to-head recompute (D-T2 rules 1/2) — happens INSIDE the store,
	// under the same lock the durable append holds. Splitting it across a
	// separate AckedSize read here and a later append opened a race: two
	// overlapping identical requests could both read the same acked size,
	// the first commit as an extend, and the second then fail the
	// exact-extend arithmetic with a plain (Internal-mapped) error instead
	// of the replay no-op success D-T2 rule 2 requires. AppendSegment
	// resolves all four outcomes atomically and returns mirrorstore.ErrConflict
	// for every "does not align" shape (gap, overlap, chain-head mismatch).
	newAcked, err := s.mirror.Store.AppendSegment(in.LogID, in.FromIndex, in.Records, in.Checkpoint)
	if err != nil {
		switch {
		case errors.Is(err, mirrorstore.ErrSignerMismatch):
			// D-T3 signer-pin failure resolved atomically in the store — a
			// writer-binding violation, same connect code as verifyMirrorIdentity's.
			return 0, fmt.Errorf("%w: mirror segment %q: %v", ErrIdentityMismatch, in.LogID, err)
		case errors.Is(err, mirrorstore.ErrConflict):
			return 0, fmt.Errorf("%w: mirror segment %q: %v", ErrMirrorConflict, in.LogID, err)
		default:
			return 0, fmt.Errorf("tlogservice: mirror segment %q: %w", in.LogID, err)
		}
	}
	return newAcked, nil
}

// verifyMirrorIdentity implements D-T3's STATELESS identity checks: it
// verifies the checkpoint's OWN signature against its SignedBy key, requires
// the wireauth-proven caller to equal the checkpoint's signer base DID, and
// applies the per-kind writer-binding predicate (emission: ancestry;
// sink-receipt/sink-reject: direct equality). The STATEFUL first-writer signer
// pin (a sibling process under the same pipeline cannot take over an existing
// log) is enforced atomically inside Store.AppendSegment instead — under the
// append lock — so it cannot be lost to a read-then-check race between two
// concurrent initial segments.
func (s *Service) verifyMirrorIdentity(ctx context.Context, kind logident.LogKind, in MirrorSegmentInput) error {
	cp := in.Checkpoint
	if cp.SignedBy == "" || len(cp.Signature) == 0 {
		return fmt.Errorf("%w: mirror segment %q: checkpoint carries no signature", ErrIdentityMismatch, in.LogID)
	}
	signerBase, err := logident.SignerBase(cp.SignedBy)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrIdentityMismatch, err)
	}
	doc, err := s.mirror.DIDResolver.Resolve(ctx, signerBase)
	if err != nil {
		// A transient resolver condition (cancellation/deadline/at-capacity)
		// means the signer's identity could NOT be evaluated — never a
		// PermissionDenied identity rejection. Surface it distinctly so the
		// handler returns a retryable code (Canceled/DeadlineExceeded/
		// Unavailable), mirroring wireauth's own resolver-error posture.
		if t := transientResolverErr(err); t != nil {
			return fmt.Errorf("tlogservice: mirror segment %q: resolve checkpoint signer %q: %w", in.LogID, signerBase, t)
		}
		return fmt.Errorf("%w: resolve checkpoint signer %q: %v", ErrIdentityMismatch, signerBase, err)
	}
	pub, err := did.ExtractPublicKey(doc, cp.SignedBy, did.RelationshipAssertionMethod)
	if err != nil {
		return fmt.Errorf("%w: checkpoint signer key: %v", ErrIdentityMismatch, err)
	}
	view, err := cp.SignedView()
	if err != nil {
		return fmt.Errorf("%w: checkpoint signed view: %v", ErrIdentityMismatch, err)
	}
	ok, verr := s.mirror.Crypto.Verify(pub, view, cp.Signature)
	if verr != nil || !ok {
		return fmt.Errorf("%w: mirror segment %q: checkpoint signature invalid", ErrIdentityMismatch, in.LogID)
	}

	if in.CallerDID != signerBase {
		return fmt.Errorf("%w: mirror segment %q: caller %q != checkpoint signer %q", ErrIdentityMismatch, in.LogID, in.CallerDID, signerBase)
	}

	owner, err := logident.OwnerDID(in.LogID)
	if err != nil {
		// Defensive: Kind (called by the caller before this) already
		// validated in.LogID through the same classifier, so this cannot
		// fail in practice.
		return fmt.Errorf("%w: %v", ErrIdentityMismatch, err)
	}

	switch kind {
	case logident.KindEmission:
		pipeline, aerr := s.mirror.Ancestry.AncestorPipeline(ctx, signerBase)
		if aerr != nil {
			// Same transient-vs-identity split as the signer resolve above: an
			// ancestry lookup that could not complete (cancellation/deadline/
			// resolver at capacity) is retryable, not a writer-binding failure.
			if t := transientResolverErr(aerr); t != nil {
				return fmt.Errorf("tlogservice: mirror segment %q: resolve signer ancestry: %w", in.LogID, t)
			}
			return fmt.Errorf("%w: resolve signer ancestry: %v", ErrIdentityMismatch, aerr)
		}
		if pipeline != owner {
			return fmt.Errorf("%w: mirror segment %q: signer %q's pipeline ancestor %q != log owner %q", ErrIdentityMismatch, in.LogID, signerBase, pipeline, owner)
		}
	default: // KindSinkReceipt, KindSinkReject
		if signerBase != owner {
			return fmt.Errorf("%w: mirror segment %q: signer %q != log owner %q", ErrIdentityMismatch, in.LogID, signerBase, owner)
		}
	}

	// The stateful first-writer signer PIN (incoming SignedBy must equal the
	// already-stored checkpoint's SignedBy) is NOT checked here: it is enforced
	// atomically inside Store.AppendSegment, under the same lock the append
	// holds, so two concurrent initial segments from different sibling signers
	// cannot both pass a read-then-check race. AppendSegment returns
	// mirrorstore.ErrSignerMismatch, which MirrorSegment maps to
	// ErrIdentityMismatch. This method does only the STATELESS identity checks
	// (signature verify, caller==signer, per-kind ancestry/equality).
	return nil
}

// transientResolverErr classifies a checkpoint-signer resolution or ancestry
// lookup failure: it returns a non-nil transient error to propagate (so the
// handler maps it to a retryable code) when the cause means "identity could
// not be evaluated at all," or nil for a genuine identity failure that should
// wear the ErrIdentityMismatch sentinel (→ PermissionDenied).
//
// It reuses the SAME classification wireauth applies to its own signer-key
// resolution (a canceled/deadline context, or the production resolver
// refusing new work at capacity, didresolver.ErrResolverBusy) and the SAME
// wireauth.ErrResolverUnavailable sentinel the handler already maps to
// Unavailable — so a transient condition here surfaces as Canceled /
// DeadlineExceeded / Unavailable, never as a PermissionDenied identity
// rejection of an honest signer.
func transientResolverErr(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return err // handler maps context.Canceled → CodeCanceled
	case errors.Is(err, context.DeadlineExceeded):
		return err // handler maps context.DeadlineExceeded → CodeDeadlineExceeded
	case errors.Is(err, didresolver.ErrResolverBusy):
		return fmt.Errorf("%w: %v", wireauth.ErrResolverUnavailable, err) // → CodeUnavailable
	}
	return nil
}
