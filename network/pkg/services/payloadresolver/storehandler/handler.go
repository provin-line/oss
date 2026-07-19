// Package storehandler is the proto↔domain boundary for PayloadStoreService's
// RetainPayload. Unlike PayloadService's L2-only serving boundary (mounted
// with NO L1 interceptor — see payloadresolver/handler), the write side is
// L1-gated (an o3co.authz.v1 policy option, mounted behind the authz
// interceptor in netcompose) PLUS an in-band wireauth proof carried in the
// first frame — the proto's own doc calls this "L1 + in-band wireauth": the
// PDP gate decides whether the caller may retain payloads AT ALL, and the
// proof additionally binds the request to a proven signer DID this handler
// requires to equal the claimed owner_did (the proven DID is authoritative).
//
// It holds no business logic beyond frame-sequencing and byte-accounting: the
// content-address derivation and durable persistence live in
// payloadresolver.Store/PayloadWriter; this package only converts proto
// frames to writer calls and Connect error codes (handler = proto↔domain +
// error mapping only, AGENTS.md). One exception: it streams directly to
// Store.StoreWriter rather than through payloadresolver.Service.Store (whose
// signature takes a whole []byte, not a stream), so it re-enforces Service's
// "no empty payload" invariant itself (errZeroDeclaredSize) — that check would
// otherwise be silently bypassed on this path.
package storehandler

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/did"
	payloadpb "github.com/provin-line/oss/gen/go/dplaax/payload/v1"
	"github.com/provin-line/oss/gen/go/dplaax/payload/v1/payloadpbconnect"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver"
)

// Verifier is the wireauth verification seam (an interface so a spy can be
// injected in tests). *wireauth.Verifier satisfies it.
type Verifier interface {
	Verify(ctx context.Context, op string, fields map[string]any, proof wireauth.Proof, authorize wireauth.Authorizer) error
}

// WriterStore is the consumer-side view of payloadresolver.Store this handler
// depends on (dependency inverted, narrowest interface for the write path —
// the read path's Owners/Get are none of this RPC's business): a streaming
// retain handle for ownerDID. payloadresolver.Store (and so *filestore.Store,
// *memstore.Store) satisfies it structurally.
type WriterStore interface {
	StoreWriter(ctx context.Context, ownerDID string) (payloadresolver.PayloadWriter, error)
}

var (
	// errEmptyStream is a stream that closed before any frame arrived.
	errEmptyStream = errors.New("storehandler: stream closed before any frame")
	// errFirstFrameNotMetadata is a stream whose first frame is not metadata
	// (a chunk, or an empty/unset frame) — the wire contract requires metadata
	// first.
	errFirstFrameNotMetadata = errors.New("storehandler: first frame must be metadata")
	// errUnexpectedMetadataFrame is a metadata frame seen after the first —
	// every subsequent frame must be a chunk.
	errUnexpectedMetadataFrame = errors.New("storehandler: metadata frame seen after the first")
	// errMalformedFrame is a frame whose oneof is unset (neither metadata nor
	// chunk) — a protocol violation.
	errMalformedFrame = errors.New("storehandler: frame carries neither metadata nor chunk")
	// errOwnerMismatch is the signer-to-actor binding failure: owner_did does
	// not equal the wireauth-proven signer DID. Mapped to PermissionDenied —
	// the proven DID is authoritative over the claimed owner_did (the proto's
	// own doc).
	errOwnerMismatch = errors.New("storehandler: owner_did does not match the proven signer")
	// errZeroDeclaredSize is a declared_size of 0. This handler streams
	// directly to Store.StoreWriter (bypassing payloadresolver.Service.Store,
	// which rejects an empty payload — "a producing process never emits an
	// empty payload; an empty by-reference payload could never bind"), so it
	// re-enforces that SAME invariant here rather than silently admitting an
	// empty-payload entry through this path. Mapped to InvalidArgument;
	// rejected before any store interaction (no writer is ever opened).
	errZeroDeclaredSize = errors.New("storehandler: declared_size must be non-zero (an empty payload is never valid)")
	// errDeclaredSizeExceeded is a declared_size above the configured
	// max-retain-payload-size quota. Mapped to ResourceExhausted; rejected
	// before any store interaction (no writer is ever opened).
	errDeclaredSizeExceeded = errors.New("storehandler: declared_size exceeds the configured quota")
	// errCumulativeOverrun is the sum of received chunk bytes exceeding
	// declared_size. Mapped to ResourceExhausted; the writer is Aborted — a
	// caller that understated its size gets nothing persisted.
	errCumulativeOverrun = errors.New("storehandler: received bytes exceed declared_size")
	// errSizeMismatch is a cleanly-closed stream whose received bytes fall
	// SHORT of declared_size (errCumulativeOverrun already catches the
	// "too many" case mid-stream, so only undershoot reaches here).
	// declared_size is a commitment, not a hint — mapped to InvalidArgument;
	// the writer is Aborted.
	errSizeMismatch = errors.New("storehandler: received bytes fall short of declared_size")
)

// Handler adapts a WriterStore to the generated PayloadStoreServiceHandler.
//
// maxPayloadSize bounds declared_size (the max-retain-payload-size quota). The
// PER-CHUNK cap (max-retain-chunk-size) is deliberately NOT a field here: it is
// enforced by the connect.WithReadMaxBytes mount option in netcompose — a
// transport-layer concern, not domain logic. A chunk over that cap never
// reaches Receive as a Chunk frame; Err() reports it instead, and this handler
// Aborts on ANY such receive error (mapError passes an already-connect-coded
// error through unchanged, so the client still sees ResourceExhausted, not a
// downgraded CodeInternal).
type Handler struct {
	store          WriterStore
	v              Verifier
	maxPayloadSize uint64
}

var _ payloadpbconnect.PayloadStoreServiceHandler = (*Handler)(nil)

// New returns a Handler backed by store and the wireauth verifier.
// maxPayloadSize is the max-retain-payload-size quota bounding declared_size.
func New(store WriterStore, v Verifier, maxPayloadSize uint64) *Handler {
	return &Handler{store: store, v: v, maxPayloadSize: maxPayloadSize}
}

// RetainPayload verifies the first frame (wireauth proof, owner_did == proven
// signer, declared_size within quota), then streams subsequent chunk frames
// to a Store.StoreWriter, enforcing the cumulative declared_size bound as it
// goes. On ANY receive error, cancellation, or validation failure once a
// writer is open, it Aborts before returning — the StoreWriter's ctx gates
// creation only (payloadresolver.Store doc), so detecting and reacting to a
// mid-stream failure is this handler's job, not the store's.
func (h *Handler) RetainPayload(ctx context.Context, stream *connect.ClientStream[payloadpb.RetainPayloadRequest]) (*connect.Response[payloadpb.RetainPayloadResponse], error) {
	if !stream.Receive() {
		if err := stream.Err(); err != nil {
			return nil, mapError(err)
		}
		return nil, connect.NewError(connect.CodeInvalidArgument, errEmptyStream)
	}
	first, ok := stream.Msg().GetFrame().(*payloadpb.RetainPayloadRequest_Metadata)
	if !ok || first.Metadata == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errFirstFrameNotMetadata)
	}
	meta := first.Metadata

	proof, err := decodeProof(meta.GetAuthProof())
	if err != nil {
		return nil, mapError(err)
	}

	declaredSize := meta.GetDeclaredSize()
	if declaredSize == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errZeroDeclaredSize)
	}
	if declaredSize > h.maxPayloadSize {
		return nil, connect.NewError(connect.CodeResourceExhausted,
			fmt.Errorf("%w: declared_size %d exceeds max %d", errDeclaredSizeExceeded, declaredSize, h.maxPayloadSize))
	}

	ownerDID := meta.GetOwnerDid()
	fields := payloadresolver.RetainPayloadFields(ownerDID, declaredSize)
	// Signer-to-actor binding: the proven signer must be the claimed owner.
	authorize := func(signerDID string, _ *did.DIDDocument, f map[string]any) error {
		if f["owner_did"] != signerDID {
			return errOwnerMismatch
		}
		return nil
	}
	if err := h.v.Verify(ctx, payloadresolver.OpRetainPayload, fields, proof, authorize); err != nil {
		return nil, mapError(err)
	}

	w, err := h.store.StoreWriter(ctx, ownerDID)
	if err != nil {
		return nil, mapError(err)
	}

	var received uint64
	for stream.Receive() {
		switch f := stream.Msg().GetFrame().(type) {
		case *payloadpb.RetainPayloadRequest_Metadata:
			_ = w.Abort()
			return nil, connect.NewError(connect.CodeInvalidArgument, errUnexpectedMetadataFrame)
		case *payloadpb.RetainPayloadRequest_Chunk:
			received += uint64(len(f.Chunk))
			if received > declaredSize {
				_ = w.Abort()
				return nil, connect.NewError(connect.CodeResourceExhausted, errCumulativeOverrun)
			}
			if _, werr := w.Write(f.Chunk); werr != nil {
				_ = w.Abort()
				return nil, mapError(werr)
			}
		default:
			_ = w.Abort()
			return nil, connect.NewError(connect.CodeInvalidArgument, errMalformedFrame)
		}
	}
	if err := stream.Err(); err != nil {
		_ = w.Abort()
		return nil, mapError(err)
	}
	if received != declaredSize {
		_ = w.Abort()
		return nil, connect.NewError(connect.CodeInvalidArgument, errSizeMismatch)
	}

	addr, err := w.Commit()
	if err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&payloadpb.RetainPayloadResponse{ContentAddress: addr}), nil
}

// mapError translates codec, wireauth, and domain sentinels to Connect codes
// (errors.Is, never string matching). An error that is ALREADY a *connect.Error
// (e.g. the mount's connect.WithReadMaxBytes cap firing mid-stream, surfaced via
// stream.Err()) is returned as-is: remapping it would downgrade an
// already-correct code (e.g. ResourceExhausted) to CodeInternal. Unrecognized
// errors become CodeInternal.
func mapError(err error) error {
	var connectErr *connect.Error
	if errors.As(err, &connectErr) {
		return connectErr
	}
	switch {
	// Malformed request / proof shape.
	case errors.Is(err, errMalformedIssuedAt),
		errors.Is(err, wireauth.ErrMissingProof),
		errors.Is(err, wireauth.ErrMalformedProof),
		errors.Is(err, wireauth.ErrInvalidView),
		errors.Is(err, payloadresolver.ErrInvalidArgument):
		return connect.NewError(connect.CodeInvalidArgument, err)
	// Inbound caller hung up mid-retain: CodeCanceled, not a server-side
	// "unavailable". Precedes ErrResolverUnavailable, which the cancellation
	// also wraps — order decides the mapping.
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	// Transient resolver condition (timeout/capacity): retryable, NOT an
	// identity rejection. Must precede the Unauthenticated cases — the error
	// also wraps ErrResolverUnavailable, and order decides the mapping.
	case errors.Is(err, wireauth.ErrResolverUnavailable):
		return connect.NewError(connect.CodeUnavailable, err)
	// Failed to prove identity.
	case errors.Is(err, wireauth.ErrExpired),
		errors.Is(err, wireauth.ErrFromFuture),
		errors.Is(err, wireauth.ErrBeforeEpoch),
		errors.Is(err, wireauth.ErrKeyResolution),
		errors.Is(err, wireauth.ErrSignatureInvalid),
		errors.Is(err, wireauth.ErrReplay):
		return connect.NewError(connect.CodeUnauthenticated, err)
	// Authorization: the proven signer is not the claimed owner.
	case errors.Is(err, errOwnerMismatch):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
