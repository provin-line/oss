// Package handler is the proto↔domain boundary for TlogService: it converts
// wire messages to and from the tlogservice domain and maps sentinel errors
// to Connect codes (errors.Is, never string matching). It holds no domain
// logic (AGENTS.md: handler = proto↔domain + error mapping only).
package handler

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"connectrpc.com/connect"

	tlogpb "github.com/provin-line/oss/gen/go/dplaax/tlog/v1"
	"github.com/provin-line/oss/gen/go/dplaax/tlog/v1/tlogpbconnect"
	"github.com/provin-line/oss/network/pkg/pagination"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
	"github.com/provin-line/oss/network/pkg/services/tlogservice"
	"github.com/provin-line/oss/tlog"
)

// Service is the consumer-side view of the tlog service the handler depends
// on (defined here to keep the dependency pointing inward).
// *tlogservice.Service satisfies it.
type Service interface {
	Checkpoint(ctx context.Context, logID string) (*tlog.Checkpoint, error)
	Records(ctx context.Context, logID string, start uint64, count int) ([]*tlog.Record, error)
	MirrorState(logID string) (uint64, error)
	MirrorSegment(ctx context.Context, in tlogservice.MirrorSegmentInput) (uint64, error)
}

// Verifier is the wireauth verification seam (an interface so a spy can be
// injected in tests). *wireauth.Verifier satisfies it.
type Verifier interface {
	Verify(ctx context.Context, op string, fields map[string]any, proof wireauth.Proof, authorize wireauth.Authorizer) error
}

// Handler adapts a Service to the generated TlogServiceHandler. Every
// method is implemented explicitly (no Unimplemented embedding — the
// compile-time completeness pin `var _ tlogpbconnect.TlogServiceHandler =
// (*Handler)(nil)` below holds with all four methods present):
// MirrorLogSegment verifies the caller's L2 wireauth proof in-band (mirrors
// auditor/handler.RegisterEvidence) before delegating D-T2/D-T3 enforcement
// to the domain Service; GetMirrorState needs no wireauth beyond the L1
// interceptor (a read RPC, same posture as ListLogRecords).
type Handler struct {
	svc Service
	v   Verifier
}

var _ tlogpbconnect.TlogServiceHandler = (*Handler)(nil)

// New returns a Handler backed by svc and the wireauth verifier v that
// MirrorLogSegment checks the caller's in-band proof against.
func New(svc Service, v Verifier) *Handler {
	return &Handler{svc: svc, v: v}
}

func (h *Handler) GetLogCheckpoint(ctx context.Context, req *connect.Request[tlogpb.GetLogCheckpointRequest]) (*connect.Response[tlogpb.GetLogCheckpointResponse], error) {
	cp, err := h.svc.Checkpoint(ctx, req.Msg.GetLogId())
	if err != nil {
		return nil, mapError(err)
	}
	// log_id is projected from the SIGNED checkpoint (cp.Origin), never
	// echoed from the request: the response value must be the one inside
	// the signature (the service already rejects an origin mismatch).
	return connect.NewResponse(&tlogpb.GetLogCheckpointResponse{
		LogId:     cp.Origin,
		Size:      strconv.FormatUint(cp.Size, 10),
		Head:      cp.Head,
		Timestamp: cp.Timestamp.UTC().Format(time.RFC3339),
		SignedBy:  cp.SignedBy,
		Signature: cp.Signature,
	}), nil
}

func (h *Handler) ListLogRecords(ctx context.Context, req *connect.Request[tlogpb.ListLogRecordsRequest]) (*connect.Response[tlogpb.ListLogRecordsResponse], error) {
	count, err := pagination.ClampSize(req.Msg.GetCount())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	start := uint64(0)
	if raw := req.Msg.GetStartIndex(); raw != "" {
		start, err = strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument,
				fmt.Errorf("start_index %q is not a decimal uint64: %w", raw, err))
		}
	}
	records, err := h.svc.Records(ctx, req.Msg.GetLogId(), start, count)
	if err != nil {
		return nil, mapError(err)
	}
	resp := &tlogpb.ListLogRecordsResponse{}
	for _, rec := range records {
		resp.Records = append(resp.Records, &tlogpb.LogRecord{
			Index:   strconv.FormatUint(rec.Index, 10),
			Payload: rec.Payload,
			Hash:    rec.Hash,
		})
	}
	return connect.NewResponse(resp), nil
}

// MirrorLogSegment verifies the caller's in-band wireauth proof (op
// tlogservice.OpMirrorLogSegment; signed fields log_id, from_index,
// checkpoint.head, segment_digest — tlogservice.MirrorLogSegmentFields /
// SegmentDigest, the SAME builders a shipper client signs with), then
// delegates D-T2 rules 2/4/5/6 and D-T3 identity enforcement to the domain
// Service. No Authorizer: the wireauth-proven signer_did is threaded
// straight through as MirrorSegmentInput.CallerDID — the domain method's
// own D-T3 predicate (checkpoint-signer equality, ancestry, pinning) is a
// richer check than a single signer-to-actor callback can express here.
func (h *Handler) MirrorLogSegment(ctx context.Context, req *connect.Request[tlogpb.MirrorLogSegmentRequest]) (*connect.Response[tlogpb.MirrorLogSegmentResponse], error) {
	proof, err := decodeProof(req.Msg.GetAuthProof())
	if err != nil {
		return nil, mapError(err)
	}
	cp, err := checkpointFromWire(req.Msg.GetCheckpoint())
	if err != nil {
		return nil, mapError(err)
	}
	digest := tlogservice.SegmentDigest(req.Msg.GetRecordPayloads())
	fields := tlogservice.MirrorLogSegmentFields(req.Msg.GetLogId(), req.Msg.GetFromIndex(), cp.Head, digest)
	if err := h.v.Verify(ctx, tlogservice.OpMirrorLogSegment, fields, proof, nil); err != nil {
		return nil, mapError(err)
	}
	acked, err := h.svc.MirrorSegment(ctx, tlogservice.MirrorSegmentInput{
		LogID:      req.Msg.GetLogId(),
		FromIndex:  req.Msg.GetFromIndex(),
		Records:    req.Msg.GetRecordPayloads(),
		Checkpoint: cp,
		CallerDID:  proof.SignerDID,
	})
	if err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&tlogpb.MirrorLogSegmentResponse{AckedSize: acked}), nil
}

// GetMirrorState returns the registry's durable mirror size for one log —
// no wireauth beyond the L1 interceptor (tlog:read), matching
// ListLogRecords' posture: it is a read RPC, not a write.
func (h *Handler) GetMirrorState(_ context.Context, req *connect.Request[tlogpb.GetMirrorStateRequest]) (*connect.Response[tlogpb.GetMirrorStateResponse], error) {
	acked, err := h.svc.MirrorState(req.Msg.GetLogId())
	if err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&tlogpb.GetMirrorStateResponse{AckedSize: acked}), nil
}

// checkpointFromWire converts a MirrorLogSegmentRequest.checkpoint
// (wire-shaped identically to GetLogCheckpointResponse) to the domain
// tlog.Checkpoint the mirror-custody surface verifies and stores. size and
// timestamp round-trip through the exact strings tlog.Checkpoint.SignedView
// re-derives its signed bytes from (decimal uint64; RFC 3339 as stamped,
// never forced to UTC — SignedView does not normalize either, so a
// non-canonical string simply fails signature verification downstream
// rather than being silently accepted or rejected here).
func checkpointFromWire(w *tlogpb.GetLogCheckpointResponse) (*tlog.Checkpoint, error) {
	if w == nil {
		return nil, fmt.Errorf("%w: missing checkpoint", tlogservice.ErrInvalidArgument)
	}
	size, err := strconv.ParseUint(w.GetSize(), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: checkpoint.size %q is not a decimal uint64: %v", tlogservice.ErrInvalidArgument, w.GetSize(), err)
	}
	ts, err := time.Parse(time.RFC3339, w.GetTimestamp())
	if err != nil {
		return nil, fmt.Errorf("%w: checkpoint.timestamp %q is not RFC 3339: %v", tlogservice.ErrInvalidArgument, w.GetTimestamp(), err)
	}
	return &tlog.Checkpoint{
		Origin:    w.GetLogId(),
		Size:      size,
		Head:      w.GetHead(),
		Timestamp: ts,
		SignedBy:  w.GetSignedBy(),
		Signature: w.GetSignature(),
	}, nil
}

// mapError translates domain sentinel errors, and MirrorLogSegment's
// wireauth sentinels, to Connect codes (errors.Is, never string matching).
// Unrecognized errors — including an unsigned log asked for a checkpoint,
// which is a node misconfiguration, never absence — become CodeInternal.
func mapError(err error) error {
	switch {
	// Malformed request / proof shape (MirrorLogSegment's codec + wireauth).
	case errors.Is(err, errMalformedIssuedAt),
		errors.Is(err, wireauth.ErrMissingProof),
		errors.Is(err, wireauth.ErrMalformedProof),
		errors.Is(err, wireauth.ErrInvalidView):
		return connect.NewError(connect.CodeInvalidArgument, err)
	// Inbound caller hung up mid-verification: CodeCanceled, not a
	// server-side "unavailable". Precedes ErrResolverUnavailable, which the
	// cancellation also wraps — order decides the mapping.
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	// Transient resolver condition (timeout/capacity): retryable, NOT an
	// identity rejection. Must precede the Unauthenticated cases — the
	// error also wraps ErrResolverUnavailable, and order decides the
	// mapping.
	case errors.Is(err, wireauth.ErrResolverUnavailable):
		return connect.NewError(connect.CodeUnavailable, err)
	// Failed to prove identity (MirrorLogSegment's wireauth verification —
	// D-T2 rule 1's proof half). Distinct from tlogservice.ErrIdentityMismatch
	// (D-T3's checkpoint/writer-binding half), which is PermissionDenied.
	case errors.Is(err, wireauth.ErrExpired),
		errors.Is(err, wireauth.ErrFromFuture),
		errors.Is(err, wireauth.ErrBeforeEpoch),
		errors.Is(err, wireauth.ErrKeyResolution),
		errors.Is(err, wireauth.ErrSignatureInvalid),
		errors.Is(err, wireauth.ErrReplay):
		return connect.NewError(connect.CodeUnauthenticated, err)
	// D-T3 identity/writer-binding failure (checkpoint signature, caller-vs-
	// signer equality, ancestry, first-segment pinning).
	case errors.Is(err, tlogservice.ErrIdentityMismatch):
		return connect.NewError(connect.CodePermissionDenied, err)
	// D-T2 rule 5 caps.
	case errors.Is(err, tlogservice.ErrCapExceeded):
		return connect.NewError(connect.CodeResourceExhausted, err)
	// D-T2 rule 1/2: a gap, a partial overlap, or a chain-head mismatch —
	// none of which is a malformed argument on their own (the request is
	// well-formed; it just does not fit the log's current state).
	case errors.Is(err, tlogservice.ErrMirrorConflict):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	// This node never wired a mirror store (cmd/standalone's map-only
	// posture) — mirrors ReportEmitHealth's "not wired" Unimplemented.
	case errors.Is(err, tlogservice.ErrMirrorNotConfigured):
		return connect.NewError(connect.CodeUnimplemented, err)
	case errors.Is(err, tlogservice.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, tlogservice.ErrInvalidArgument):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
