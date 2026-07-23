// Package handler is the proto↔domain boundary for the chainmanager services. It
// converts connect request/response messages to and from the chainmanager domain
// and maps domain sentinel errors to Connect codes; it holds no business logic.
//
// OperatorHandler serves the L1 ChainService (operator surface); PeerHandler
// serves the L2 ChainPeerService (wireauth-verified). The operator's
// connection-flow RPCs (Subscribe/Unsubscribe) are enabled via WithSubscriber.
package handler

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/provin-line/oss/allowlist"
	"github.com/provin-line/oss/did"
	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	"github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
	"github.com/provin-line/oss/network/pkg/services/chainmanager"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
)

// Service is the consumer-side view of the chainmanager domain the operator
// handler depends on (defined here, not in the service package, to keep the
// dependency pointing inward). *chainmanager.Service satisfies it.
type Service interface {
	ListSubscriptions(ctx context.Context) ([]*store.Subscription, error)
	UpdateAllowList(ctx context.Context, pipelineDID string, patterns []string) error
}

// AllowListReader is the read half of the allow-list capability. It is wired
// separately from Service (via WithAllowListReader) so adding allow-list read
// does not widen the exported Service interface — external Service
// implementations keep compiling (D-s9, mirroring WithSubscriber).
// *chainmanager.Service satisfies it.
type AllowListReader interface {
	GetAllowList(ctx context.Context, pipelineDID string) ([]store.AllowRule, error)
}

// EmitHealthReporter is the consumer-side view of the emit-health store the
// handler depends on (defined here, not in the emithealth package, to keep
// the dependency pointing inward — mirrors Service/AllowListReader above).
// *emithealth.Store satisfies it structurally.
type EmitHealthReporter interface {
	Report(publisherDID string, healthy bool, now time.Time)
}

// OperatorHandler adapts a Service to the generated ChainServiceHandler. It
// embeds the Unimplemented stub so the connection-flow RPCs (Subscribe /
// Unsubscribe) return CodeUnimplemented until a SubscriberService is supplied via
// WithSubscriber; the two operator-local RPCs are always implemented here.
type OperatorHandler struct {
	chainpbconnect.UnimplementedChainServiceHandler
	svc   Service
	sub   SubscriberService // nil → Subscribe/Unsubscribe report Unimplemented
	allow AllowListReader   // nil → GetAllowList reports Unimplemented

	// ReportEmitHealth wiring (WithEmitHealth). emitHealth is nil unless
	// wired, in which case ReportEmitHealth reports Unimplemented — mirrors
	// allow's nil posture above (production always wires it on cmd/network).
	emitHealth         EmitHealthReporter
	emitHealthVerifier Verifier
	emitHealthTTL      time.Duration
}

var _ chainpbconnect.ChainServiceHandler = (*OperatorHandler)(nil)

// OperatorOption configures an OperatorHandler at construction.
type OperatorOption func(*OperatorHandler)

// WithSubscriber enables the connection-flow RPCs (Subscribe / Unsubscribe) by
// supplying the subscriber-side service. Kept separate from Service (D-s9) so the
// exported Service interface is not widened — external fakes implementing Service
// keep compiling.
func WithSubscriber(sub SubscriberService) OperatorOption {
	return func(h *OperatorHandler) { h.sub = sub }
}

// WithAllowListReader enables the GetAllowList RPC. Kept separate from Service
// (like WithSubscriber) so the exported Service interface is not widened.
// Production wiring always supplies it; without it GetAllowList reports
// Unimplemented.
func WithAllowListReader(r AllowListReader) OperatorOption {
	return func(h *OperatorHandler) { h.allow = r }
}

// WithEmitHealth enables the ReportEmitHealth RPC: reporter records each
// verified report (typically an *emithealth.Store, the SAME instance the
// composition root's chainmanager.WithPublisherHealth lookup reads back — see
// internal/netcompose's cmd/network wiring), v verifies the caller's in-band
// wireauth proof (ReportEmitHealth is "L1 + wireauth", per the proto's own
// doc), and ttl is the freshness window echoed back in every response.
// Without this option ReportEmitHealth reports Unimplemented; production
// wires it on cmd/network.
func WithEmitHealth(reporter EmitHealthReporter, v Verifier, ttl time.Duration) OperatorOption {
	return func(h *OperatorHandler) {
		h.emitHealth = reporter
		h.emitHealthVerifier = v
		h.emitHealthTTL = ttl
	}
}

// NewOperator returns an OperatorHandler backed by svc. Pass WithSubscriber to
// enable the connection-flow RPCs.
func NewOperator(svc Service, opts ...OperatorOption) *OperatorHandler {
	h := &OperatorHandler{svc: svc}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

func (h *OperatorHandler) ListSubscriptions(ctx context.Context, req *connect.Request[chainpb.ListSubscriptionsRequest]) (*connect.Response[chainpb.ListSubscriptionsResponse], error) {
	subs, err := h.svc.ListSubscriptions(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]*chainpb.Subscription, len(subs))
	for i, s := range subs {
		out[i] = toProtoSubscription(s)
	}
	return connect.NewResponse(&chainpb.ListSubscriptionsResponse{Subscriptions: out}), nil
}

func (h *OperatorHandler) UpdateAllowList(ctx context.Context, req *connect.Request[chainpb.UpdateAllowListRequest]) (*connect.Response[chainpb.UpdateAllowListResponse], error) {
	rules := req.Msg.GetRules()
	patterns := make([]string, len(rules))
	for i, r := range rules {
		patterns[i] = r.GetPattern()
	}
	if err := h.svc.UpdateAllowList(ctx, req.Msg.GetPipelineDid(), patterns); err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&chainpb.UpdateAllowListResponse{}), nil
}

// errPublisherMismatch is ReportEmitHealth's signer-to-actor binding failure:
// the proof's signer is not the publisher_did the request claims to report
// health for. Mapped to PermissionDenied — the proven DID is authoritative
// over publisher_did (the proto's own doc: "a caller reports health only for
// itself").
var errPublisherMismatch = errors.New("chainmanager: signer is not the claimed publisher")

// ReportEmitHealth verifies the caller's in-band wireauth proof (L1 +
// wireauth, per ReportEmitHealthRequest's own doc), rejects a publisher_did
// that does not equal the proven signer DID (PermissionDenied — a caller may
// only report health for itself), then records the report and returns the
// server's configured TTL.
func (h *OperatorHandler) ReportEmitHealth(ctx context.Context, req *connect.Request[chainpb.ReportEmitHealthRequest]) (*connect.Response[chainpb.ReportEmitHealthResponse], error) {
	if h.emitHealth == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("chainmanager: ReportEmitHealth not wired (WithEmitHealth)"))
	}
	proof, err := decodeProof(req.Msg.GetAuthProof())
	if err != nil {
		return nil, mapError(err)
	}
	fields := chainmanager.ReportEmitHealthFields(req.Msg.GetPublisherDid(), req.Msg.GetHealthy())
	// Signer-to-actor binding: the proven signer must be the claimed publisher.
	bind := func(signerDID string, _ *did.DIDDocument, f map[string]any) error {
		if f["publisher_did"] != signerDID {
			return errPublisherMismatch
		}
		return nil
	}
	if err := h.emitHealthVerifier.Verify(ctx, chainmanager.OpReportEmitHealth, fields, proof, bind); err != nil {
		return nil, mapError(err)
	}
	h.emitHealth.Report(req.Msg.GetPublisherDid(), req.Msg.GetHealthy(), time.Now())
	return connect.NewResponse(&chainpb.ReportEmitHealthResponse{Ttl: durationpb.New(h.emitHealthTTL)}), nil
}

func (h *OperatorHandler) GetAllowList(ctx context.Context, req *connect.Request[chainpb.GetAllowListRequest]) (*connect.Response[chainpb.GetAllowListResponse], error) {
	if h.allow == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("chainmanager: GetAllowList not wired (WithAllowListReader)"))
	}
	rules, err := h.allow.GetAllowList(ctx, req.Msg.GetPipelineDid())
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]*chainpb.AllowRule, len(rules))
	for i, r := range rules {
		out[i] = &chainpb.AllowRule{Pattern: r.Pattern}
	}
	return connect.NewResponse(&chainpb.GetAllowListResponse{Rules: out}), nil
}

// toProtoSubscription maps a domain subscription to the wire message. Created is
// formatted as a canonical RFC 3339 UTC second-precision string (the format half
// of the codec; the wire carries no inbound Created). A zero Created maps to the
// empty string rather than the year-0001 sentinel.
func toProtoSubscription(s *store.Subscription) *chainpb.Subscription {
	return &chainpb.Subscription{
		Id:              s.ID,
		SubscriberDid:   s.SubscriberDID,
		PublisherDid:    s.PublisherDID,
		PublishType:     s.PublishType,
		PayloadDelivery: s.PayloadDelivery,
		ConnectionInfo:  s.ConnectionInfo,
		Created:         formatCreated(s.Created),
	}
}

func formatCreated(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Truncate(time.Second).Format(time.RFC3339)
}

// mapError translates domain sentinel errors, and ReportEmitHealth's wireauth
// sentinels, to Connect codes (errors.Is, never string matching).
func mapError(err error) error {
	switch {
	// Malformed request / proof shape (ReportEmitHealth's codec + wireauth).
	case errors.Is(err, errMalformedIssuedAt),
		errors.Is(err, wireauth.ErrMissingProof),
		errors.Is(err, wireauth.ErrMalformedProof),
		errors.Is(err, wireauth.ErrInvalidView):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, allowlist.ErrInvalidPattern):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, chainmanager.ErrInvalidPipelineDID):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, chainmanager.ErrInvalidSubscriberDID):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, chainmanager.ErrEndpointNotAllowed):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, chainmanager.ErrPayloadModeUnsupported):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, chainmanager.ErrDuplicateSubscription):
		// D-4 mixed-mode invariant, subscriber-side (authoritative): a
		// subscription to this publisher already exists — a create-conflict.
		return connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, chainmanager.ErrNoChainManagerEndpoint):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, chainmanager.ErrSubscriberUnconfigured):
		return connect.NewError(connect.CodeInternal, err)
	case errors.Is(err, chainmanager.ErrRemotePeer):
		// Pass the remote ConnectRPC code through when present (D-s8): a remote
		// PermissionDenied/InvalidArgument/etc. is preserved in the error chain
		// (%w), so the operator gets the right recoverability signal; an opaque
		// failure (e.g. a resolver error) maps to Unavailable.
		if code := connect.CodeOf(err); code != connect.CodeUnknown {
			return connect.NewError(code, err)
		}
		return connect.NewError(connect.CodeUnavailable, err)
	// Inbound caller hung up mid-verification: CodeCanceled, not a
	// server-side "unavailable". Precedes ErrResolverUnavailable, which the
	// cancellation also wraps — order decides the mapping.
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	// Transient resolver condition (timeout/capacity): retryable, NOT an
	// identity rejection. Must precede the Unauthenticated cases — the error
	// also wraps ErrResolverUnavailable, and order decides the mapping.
	case errors.Is(err, wireauth.ErrResolverUnavailable):
		return connect.NewError(connect.CodeUnavailable, err)
	// Failed to prove identity (ReportEmitHealth's wireauth verification).
	case errors.Is(err, wireauth.ErrExpired),
		errors.Is(err, wireauth.ErrFromFuture),
		errors.Is(err, wireauth.ErrBeforeEpoch),
		errors.Is(err, wireauth.ErrKeyResolution),
		errors.Is(err, wireauth.ErrSignatureInvalid),
		errors.Is(err, wireauth.ErrReplay):
		return connect.NewError(connect.CodeUnauthenticated, err)
	// Signer-to-actor binding: the proven signer must be the claimed publisher.
	case errors.Is(err, errPublisherMismatch):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, store.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
