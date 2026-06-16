package handler

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/did"
	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	"github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
	"github.com/provin-line/oss/network/pkg/services/chainmanager"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
)

// PeerService is the consumer-side view of the chainmanager peer domain the
// handler depends on (defined here so the dependency points inward).
// *chainmanager.Service satisfies it.
type PeerService interface {
	PublisherInfo(ctx context.Context, publisherDID, callerDID string) (string, []string, error)
	RegisterSubscription(ctx context.Context, subscriberDID, publisherDID, requestedMode string) (*store.Subscription, error)
	Disconnect(ctx context.Context, subscriptionID, callerDID string) error
}

// Verifier is the wireauth verification seam the handler depends on (an interface
// so a spy can be injected in tests). *wireauth.Verifier satisfies it.
type Verifier interface {
	Verify(ctx context.Context, op string, fields map[string]any, proof wireauth.Proof, authorize wireauth.Authorizer) error
}

// errSignerMismatch is the signer-to-actor binding failure (the proof's signer is
// not the actor the request claims). Mapped to PermissionDenied.
var errSignerMismatch = errors.New("chainmanager: signer is not the claimed actor")

// PeerHandler adapts a PeerService to the generated ChainPeerServiceHandler. Each
// RPC decodes the AuthProof (strict issued_at codec), reconstructs the per-op
// signed view, verifies it in-band via wireauth (L2 — no L1 interceptor), and
// only then calls the domain.
type PeerHandler struct {
	svc PeerService
	v   Verifier
}

var _ chainpbconnect.ChainPeerServiceHandler = (*PeerHandler)(nil)

// NewPeer returns a PeerHandler backed by svc and the wireauth verifier.
func NewPeer(svc PeerService, v Verifier) *PeerHandler {
	return &PeerHandler{svc: svc, v: v}
}

func (h *PeerHandler) GetPublisherInfo(ctx context.Context, req *connect.Request[chainpb.GetPublisherInfoRequest]) (*connect.Response[chainpb.GetPublisherInfoResponse], error) {
	proof, err := decodeProof(req.Msg.GetAuthProof())
	if err != nil {
		return nil, peerMapError(err)
	}
	fields := map[string]any{"publisher_did": req.Msg.GetPublisherDid()}
	// No separate actor field: the querying actor IS the signer (nil authorizer).
	if err := h.v.Verify(ctx, "GetPublisherInfo", fields, proof, nil); err != nil {
		return nil, peerMapError(err)
	}
	pubType, modes, err := h.svc.PublisherInfo(ctx, req.Msg.GetPublisherDid(), proof.SignerDID)
	if err != nil {
		return nil, peerMapError(err)
	}
	return connect.NewResponse(&chainpb.GetPublisherInfoResponse{
		PublishType:              pubType,
		SupportedPayloadDelivery: modes,
	}), nil
}

func (h *PeerHandler) RegisterSubscription(ctx context.Context, req *connect.Request[chainpb.RegisterSubscriptionRequest]) (*connect.Response[chainpb.RegisterSubscriptionResponse], error) {
	proof, err := decodeProof(req.Msg.GetAuthProof())
	if err != nil {
		return nil, peerMapError(err)
	}
	// payload_delivery is signed verbatim (incl. empty); empty→by-reference
	// negotiation happens in the domain after verification, never in the view.
	fields := map[string]any{
		"subscriber_did":   req.Msg.GetSubscriberDid(),
		"publisher_did":    req.Msg.GetPublisherDid(),
		"payload_delivery": req.Msg.GetPayloadDelivery(),
	}
	// Signer-to-actor binding: the signer must be the subscriber it claims to be.
	bind := func(signerDID string, _ *did.DIDDocument, f map[string]any) error {
		if f["subscriber_did"] != signerDID {
			return errSignerMismatch
		}
		return nil
	}
	if err := h.v.Verify(ctx, "RegisterSubscription", fields, proof, bind); err != nil {
		return nil, peerMapError(err)
	}
	sub, err := h.svc.RegisterSubscription(ctx, req.Msg.GetSubscriberDid(), req.Msg.GetPublisherDid(), req.Msg.GetPayloadDelivery())
	if err != nil {
		return nil, peerMapError(err)
	}
	return connect.NewResponse(&chainpb.RegisterSubscriptionResponse{
		SubscriptionId:  sub.ID,
		ConnectionInfo:  sub.ConnectionInfo,
		PublishType:     sub.PublishType,
		PayloadDelivery: sub.PayloadDelivery,
	}), nil
}

func (h *PeerHandler) Disconnect(ctx context.Context, req *connect.Request[chainpb.DisconnectRequest]) (*connect.Response[chainpb.DisconnectResponse], error) {
	proof, err := decodeProof(req.Msg.GetAuthProof())
	if err != nil {
		return nil, peerMapError(err)
	}
	fields := map[string]any{"subscription_id": req.Msg.GetSubscriptionId()}
	// Ownership requires stored state, so it is checked in the domain (the actor
	// is the signer; no separate actor field to bind here).
	if err := h.v.Verify(ctx, "Disconnect", fields, proof, nil); err != nil {
		return nil, peerMapError(err)
	}
	if err := h.svc.Disconnect(ctx, req.Msg.GetSubscriptionId(), proof.SignerDID); err != nil {
		return nil, peerMapError(err)
	}
	return connect.NewResponse(&chainpb.DisconnectResponse{}), nil
}

// decodeProof converts the wire AuthProof to a wireauth.Proof, parsing issued_at
// through the strict codec. A nil proof is ErrMissingProof.
func decodeProof(ap *chainpb.AuthProof) (wireauth.Proof, error) {
	if ap == nil {
		return wireauth.Proof{}, wireauth.ErrMissingProof
	}
	issuedAt, err := parseIssuedAt(ap.GetIssuedAt())
	if err != nil {
		return wireauth.Proof{}, err
	}
	return wireauth.Proof{
		SignerDID: ap.GetSignerDid(),
		Nonce:     ap.GetNonce(),
		IssuedAt:  issuedAt,
		Signature: ap.GetSignature(),
	}, nil
}

// peerMapError maps codec, wireauth, and domain sentinels to connect codes
// (errors.Is, never string matching) — slice-11 D-p9.
func peerMapError(err error) error {
	switch {
	// Malformed request / proof shape.
	case errors.Is(err, errMalformedIssuedAt),
		errors.Is(err, wireauth.ErrMissingProof),
		errors.Is(err, wireauth.ErrMalformedProof),
		errors.Is(err, wireauth.ErrInvalidView):
		return connect.NewError(connect.CodeInvalidArgument, err)
	// Failed to prove identity.
	case errors.Is(err, wireauth.ErrExpired),
		errors.Is(err, wireauth.ErrFromFuture),
		errors.Is(err, wireauth.ErrBeforeEpoch),
		errors.Is(err, wireauth.ErrKeyResolution),
		errors.Is(err, wireauth.ErrSignatureInvalid),
		errors.Is(err, wireauth.ErrReplay):
		return connect.NewError(connect.CodeUnauthenticated, err)
	// Authorization (signer-binding, allow-list, ownership).
	case errors.Is(err, errSignerMismatch),
		errors.Is(err, chainmanager.ErrNotAdmitted),
		errors.Is(err, chainmanager.ErrNotOwner):
		return connect.NewError(connect.CodePermissionDenied, err)
	// Invalid arguments.
	case errors.Is(err, chainmanager.ErrPayloadModeUnsupported),
		errors.Is(err, chainmanager.ErrInvalidPipelineDID):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, store.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, chainmanager.ErrInfraUnavailable):
		return connect.NewError(connect.CodeInternal, err)
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
