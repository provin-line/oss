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

	"github.com/provin-line/oss/allowlist"
	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	"github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
	"github.com/provin-line/oss/network/pkg/services/chainmanager"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
)

// Service is the consumer-side view of the chainmanager domain the operator
// handler depends on (defined here, not in the service package, to keep the
// dependency pointing inward). *chainmanager.Service satisfies it.
type Service interface {
	ListSubscriptions(ctx context.Context) ([]*store.Subscription, error)
	UpdateAllowList(ctx context.Context, pipelineDID string, patterns []string) error
}

// OperatorHandler adapts a Service to the generated ChainServiceHandler. It
// embeds the Unimplemented stub so the connection-flow RPCs (Subscribe /
// Unsubscribe) return CodeUnimplemented until a SubscriberService is supplied via
// WithSubscriber; the two operator-local RPCs are always implemented here.
type OperatorHandler struct {
	chainpbconnect.UnimplementedChainServiceHandler
	svc Service
	sub SubscriberService // nil → Subscribe/Unsubscribe report Unimplemented
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

// mapError translates domain sentinel errors to Connect codes (errors.Is, never
// string matching).
func mapError(err error) error {
	switch {
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
	case errors.Is(err, store.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
