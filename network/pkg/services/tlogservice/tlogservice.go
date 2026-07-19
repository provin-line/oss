// Package tlogservice is the read service behind dplaax.tlog.v1.TlogService:
// a registry of the node's per-loop emission logs (keyed by log id = the
// producing loop's output subject), serving signed checkpoints and record
// ranges for transport-loss reconciliation. It owns the domain logic
// (registry lookup, range bounds); the logs are the tlog implementations
// and the handler is pure proto↔domain conversion.
package tlogservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/did"
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
type MirrorStore interface {
	AckedSize(logID string) (uint64, error)
	Checkpoint(logID string) (*tlog.Checkpoint, error)
	Get(logID string, index uint64) (*tlog.Record, error)
	AppendVerified(logID string, records [][]byte, cp *tlog.Checkpoint) (uint64, error)
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
		cp, err := s.mirror.Store.Checkpoint(logID)
		if err != nil {
			if errors.Is(err, mirrorstore.ErrNotFound) {
				return nil, fmt.Errorf("%w: %q", ErrNotFound, logID)
			}
			return nil, fmt.Errorf("tlogservice: checkpoint %q: %w", logID, err)
		}
		// mirrorstore.AppendVerified already enforces cp.Origin == logID at
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
//  3. alignment / extend / overflow (rules 1, 2) — ErrInvalidArgument
//     (overflow, checkpoint.size misaligned) or ErrMirrorConflict (gap,
//     partial overlap).
//  4. chain-to-head (rule 1) — ErrMirrorConflict (FailedPrecondition).
//  5. store.AppendVerified (rule 6; monotonicity is enforced by the store).
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
	// catching it here keeps mirrorstore.AppendVerified's own Origin==logID
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

	if len(in.Records) > s.mirror.MaxBatchRecords {
		return 0, fmt.Errorf("%w: %d records exceeds max-batch-records %d", ErrCapExceeded, len(in.Records), s.mirror.MaxBatchRecords)
	}
	var totalBytes int
	for _, p := range in.Records {
		totalBytes += len(p)
	}
	if totalBytes > s.mirror.MaxBatchBytes {
		return 0, fmt.Errorf("%w: %d bytes exceeds max-batch-bytes %d", ErrCapExceeded, totalBytes, s.mirror.MaxBatchBytes)
	}

	total := in.FromIndex + uint64(len(in.Records))
	if total < in.FromIndex {
		return 0, fmt.Errorf("%w: mirror segment %q: from_index %d + %d records overflows uint64", ErrInvalidArgument, in.LogID, in.FromIndex, len(in.Records))
	}
	if in.Checkpoint.Size != total {
		return 0, fmt.Errorf("%w: mirror segment %q: checkpoint.size %d != from_index %d + %d records", ErrInvalidArgument, in.LogID, in.Checkpoint.Size, in.FromIndex, len(in.Records))
	}

	acked, err := s.mirror.Store.AckedSize(in.LogID)
	if err != nil {
		return 0, fmt.Errorf("tlogservice: mirror segment %q: %w", in.LogID, err)
	}

	switch {
	case in.FromIndex > acked:
		return 0, fmt.Errorf("%w: mirror segment %q: from_index %d is ahead of the acked size %d (a gap)", ErrMirrorConflict, in.LogID, in.FromIndex, acked)
	case in.FromIndex < acked:
		// A replay range that extends PAST the acked size is a partial
		// overlap, not a clean replay: [from_index, total) re-includes an
		// already-mirrored prefix AND claims records beyond what is
		// acked. Reject it up front — left unchecked, the byte-compare
		// loop below would run Store.Get past the acked size, whose plain
		// out-of-range error is not sentinel-mapped and would surface as
		// CodeInternal instead of the FailedPrecondition D-T2 rule 2
		// requires for every overlap shape.
		if total > acked {
			return 0, fmt.Errorf("%w: mirror segment %q: replay range [%d,%d) extends past the acked size %d (partial overlap)", ErrMirrorConflict, in.LogID, in.FromIndex, total, acked)
		}
		// Replay range: every requested record must byte-match what this
		// store already holds at that position (D-T2 rule 2's
		// byte-identical no-op). mirrorstore.AppendVerified does not accept
		// a stale checkpoint carrying non-empty records (see its doc), so a
		// replay with records is resolved HERE, without ever calling it.
		for i, payload := range in.Records {
			stored, gerr := s.mirror.Store.Get(in.LogID, in.FromIndex+uint64(i))
			if gerr != nil {
				return 0, fmt.Errorf("tlogservice: mirror segment %q: %w", in.LogID, gerr)
			}
			if !bytes.Equal(stored.Payload, payload) {
				return 0, fmt.Errorf("%w: mirror segment %q: record at index %d does not byte-match the already-mirrored record (partial overlap)", ErrMirrorConflict, in.LogID, in.FromIndex+uint64(i))
			}
		}
		return acked, nil // byte-identical replay — no-op success
	}

	// Exact extend: recompute the chain head from the stored tail through
	// the segment (rule 1) BEFORE calling the store, so a mismatch surfaces
	// the precise connect code — mirrorstore.AppendVerified re-checks this
	// itself as defense in depth, but its own error is not sentinel-mapped.
	tail := ""
	if acked > 0 {
		last, gerr := s.mirror.Store.Get(in.LogID, acked-1)
		if gerr != nil {
			return 0, fmt.Errorf("tlogservice: mirror segment %q: %w", in.LogID, gerr)
		}
		tail = last.Hash
	}
	head := tail
	for _, payload := range in.Records {
		head = mirrorstore.ChainHash(head, payload)
	}
	if head != in.Checkpoint.Head {
		return 0, fmt.Errorf("%w: mirror segment %q: recomputed chain head %q != checkpoint head %q", ErrMirrorConflict, in.LogID, head, in.Checkpoint.Head)
	}

	newAcked, err := s.mirror.Store.AppendVerified(in.LogID, in.Records, in.Checkpoint)
	if err != nil {
		return 0, fmt.Errorf("tlogservice: mirror segment %q: %w", in.LogID, err)
	}
	return newAcked, nil
}

// verifyMirrorIdentity implements D-T3: verifies the checkpoint's OWN
// signature against its SignedBy key, requires the wireauth-proven caller
// to equal the checkpoint's signer base DID, applies the per-kind
// writer-binding predicate (emission: ancestry; sink-receipt/sink-reject:
// direct equality), and — once the log already carries a persisted
// checkpoint — pins the exact signer (SignedBy, the full verification
// method, not just its base DID): a sibling process under the same
// pipeline cannot take over an existing log.
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

	// First-accepted-segment pinning.
	existing, cerr := s.mirror.Store.Checkpoint(in.LogID)
	switch {
	case cerr == nil:
		if existing.SignedBy != cp.SignedBy {
			return fmt.Errorf("%w: mirror segment %q: signer %q does not match the log's pinned signer %q", ErrIdentityMismatch, in.LogID, cp.SignedBy, existing.SignedBy)
		}
	case errors.Is(cerr, mirrorstore.ErrNotFound):
		// First segment for this log — nothing to pin against yet.
	default:
		return fmt.Errorf("tlogservice: mirror segment %q: pinning check: %w", in.LogID, cerr)
	}
	return nil
}
