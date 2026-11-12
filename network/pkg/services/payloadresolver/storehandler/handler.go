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
// It converts proto frames to calls and Connect error codes only (handler =
// proto↔domain + error mapping, AGENTS.md): it sequences the frames, has the
// proof verified, parses the content_address, and aborts the writer when the
// stream fails or a frame is out of sequence. Whether the payload is kept is
// payloadresolver/internal/retention's: the declared size (not zero, within
// the quota), the bytes against it and against the content_address, and
// committing the writer, or aborting it when the bytes do not meet them. The
// content-address derivation and durable persistence live in
// payloadresolver.Store/PayloadWriter.
package storehandler

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/contentaddress"
	"github.com/provin-line/oss/did"
	payloadpb "github.com/provin-line/oss/gen/go/dplaax/payload/v1"
	"github.com/provin-line/oss/gen/go/dplaax/payload/v1/payloadpbconnect"
	"github.com/provin-line/oss/network/internal/authproof"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver/internal/retention"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver/wirecontract"
	"github.com/provin-line/oss/network/pkg/wireauth"
	"github.com/provin-line/oss/network/pkg/wireautherr"
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
	// errZeroDeclaredSize is a declared_size of 0 (retention.ErrEmpty), the
	// same invariant as payloadresolver.Service.Store's: "a producing process
	// never emits an empty payload; an empty by-reference payload could never
	// bind". Mapped to InvalidArgument; rejected before any store interaction
	// (no writer is ever opened).
	errZeroDeclaredSize = errors.New("storehandler: declared_size must be non-zero (an empty payload is never valid)")
	// errMalformedContentAddress is a metadata frame whose content_address is
	// missing or not spelled as an address ("sha256:" and 64 lowercase hex
	// digits), as from a client of an earlier release, which sends none.
	// Mapped to InvalidArgument; rejected before the proof is verified (the
	// proof covers the address) and before any writer is opened.
	errMalformedContentAddress = errors.New("storehandler: content_address is missing or not an address")
	// errContentAddressMismatch is a stream whose bytes are not the ones its
	// declared content_address names (retention.ErrAddressMismatch): the store
	// keeps nothing (InvalidArgument, as for a declared_size the bytes do not
	// meet).
	errContentAddressMismatch = errors.New("storehandler: the payload's bytes are not the ones its content_address names")
	// errDeclaredSizeExceeded is a declared_size above the configured
	// max-retain-payload-size quota (retention.ErrOverQuota). Mapped to
	// ResourceExhausted; rejected before any store interaction (no writer is
	// ever opened).
	errDeclaredSizeExceeded = errors.New("storehandler: declared_size exceeds the configured quota")
	// errCumulativeOverrun is the sum of received chunk bytes exceeding
	// declared_size (retention.ErrOverrun). Mapped to ResourceExhausted; the
	// writer is Aborted — a caller that understated its size gets nothing
	// persisted.
	errCumulativeOverrun = errors.New("storehandler: received bytes exceed declared_size")
	// errSizeMismatch is a cleanly-closed stream whose received bytes fall
	// SHORT of declared_size (retention.ErrShort; errCumulativeOverrun already
	// catches the "too many" case mid-stream, so only undershoot reaches
	// here). declared_size is a commitment, not a hint — mapped to
	// InvalidArgument; the writer is Aborted.
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

// RetainPayload verifies the first frame (declared_size within quota, a
// content_address spelled as one, then the wireauth proof over owner_did,
// declared_size and content_address with owner_did == proven signer), then
// streams subsequent chunk frames through a retention.Retention to a
// Store.StoreWriter, which keeps the bytes only when they meet declared_size
// and have the declared content_address. On ANY receive error, cancellation,
// or frame out of sequence once a writer is open, it Aborts before returning
// — the StoreWriter's ctx gates creation only (payloadresolver.Store doc), so
// detecting and reacting to a mid-stream failure is this handler's job, not
// the store's.
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

	proof, err := authproof.Decode(meta.GetAuthProof())
	if err != nil {
		return nil, mapError(err)
	}

	declaredSize := meta.GetDeclaredSize()
	declared, err := retention.Declare(declaredSize, h.maxPayloadSize)
	if err != nil {
		return nil, h.retentionError(err, declaredSize)
	}

	contentAddress, err := contentaddress.Parse(meta.GetContentAddress())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("%w: %w", errMalformedContentAddress, err))
	}

	ownerDID := meta.GetOwnerDid()
	fields := wirecontract.RetainPayloadFields(ownerDID, declaredSize, contentAddress)
	// Signer-to-actor binding: the proven signer must be the claimed owner.
	authorize := func(signerDID string, _ *did.DIDDocument, f map[string]any) error {
		if f["owner_did"] != signerDID {
			return errOwnerMismatch
		}
		return nil
	}
	if err := h.v.Verify(ctx, wirecontract.OpRetainPayload, fields, proof, authorize); err != nil {
		return nil, mapError(err)
	}

	w, err := h.store.StoreWriter(ctx, ownerDID)
	if err != nil {
		return nil, mapError(err)
	}

	r := retention.New(w, declared, contentAddress)
	for stream.Receive() {
		switch f := stream.Msg().GetFrame().(type) {
		case *payloadpb.RetainPayloadRequest_Metadata:
			_ = r.Abort()
			return nil, connect.NewError(connect.CodeInvalidArgument, errUnexpectedMetadataFrame)
		case *payloadpb.RetainPayloadRequest_Chunk:
			if err := r.Write(f.Chunk); err != nil {
				return nil, h.retentionError(err, declaredSize)
			}
		default:
			_ = r.Abort()
			return nil, connect.NewError(connect.CodeInvalidArgument, errMalformedFrame)
		}
	}
	if err := stream.Err(); err != nil {
		_ = r.Abort()
		return nil, mapError(err)
	}

	addr, err := r.Commit()
	if err != nil {
		return nil, h.retentionError(err, declaredSize)
	}
	return connect.NewResponse(&payloadpb.RetainPayloadResponse{ContentAddress: addr}), nil
}

// retentionError is err from retention as this RPC answers it: the sentinel
// and code of the check that refused, or mapError's answer for the writer's
// own error, which retention returns as it is.
func (h *Handler) retentionError(err error, declaredSize uint64) error {
	switch {
	case errors.Is(err, retention.ErrEmpty):
		return connect.NewError(connect.CodeInvalidArgument, errZeroDeclaredSize)
	case errors.Is(err, retention.ErrOverQuota):
		return connect.NewError(connect.CodeResourceExhausted,
			fmt.Errorf("%w: declared_size %d exceeds max %d", errDeclaredSizeExceeded, declaredSize, h.maxPayloadSize))
	case errors.Is(err, retention.ErrOverrun):
		return connect.NewError(connect.CodeResourceExhausted, errCumulativeOverrun)
	case errors.Is(err, retention.ErrShort):
		return connect.NewError(connect.CodeInvalidArgument, errSizeMismatch)
	case errors.Is(err, retention.ErrAddressMismatch):
		return connect.NewError(connect.CodeInvalidArgument, errContentAddressMismatch)
	}
	return mapError(err)
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
	// Malformed request (issued_at codec + domain-level argument errors).
	// Wireauth's own structural sentinels are handled by the wireautherr
	// delegation below.
	case errors.Is(err, authproof.ErrMalformedIssuedAt),
		errors.Is(err, payloadresolver.ErrInvalidArgument):
		return connect.NewError(connect.CodeInvalidArgument, err)
	// Inbound caller hung up mid-retain: CodeCanceled, not a server-side
	// "unavailable". Precedes the wireautherr delegation below, which the
	// cancellation can also wrap (ErrResolverUnavailable) — order decides the
	// mapping.
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	}
	// Wireauth verification (structural, transient-resolver, and identity
	// sentinels), delegated to the shared classifier so this mapping cannot
	// drift from the other 5 handlers.
	if code, ok := wireautherr.Code(err); ok {
		return connect.NewError(code, err)
	}
	switch {
	// Authorization: the proven signer is not the claimed owner.
	case errors.Is(err, errOwnerMismatch):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
