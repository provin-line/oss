package handler

import (
	"context"

	"connectrpc.com/connect"

	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
)

// SubscriberService is the consumer-side view of the chainmanager domain's
// outbound connection flow (the L1 Subscribe / Unsubscribe RPCs). It is declared
// separately from Service (D-s9) so enabling the connection flow does not widen
// the exported Service interface — external fakes implementing Service keep
// compiling. *chainmanager.Service satisfies it.
type SubscriberService interface {
	Subscribe(ctx context.Context, subscriberDID, publisherDID, requestedMode string) (string, error)
	Unsubscribe(ctx context.Context, subscriptionID string) error
}

// Subscribe drives this CM to subscribe a local pipeline to a remote publisher.
// Without a configured SubscriberService it reports CodeUnimplemented (the
// embedded stub's behavior).
func (h *OperatorHandler) Subscribe(ctx context.Context, req *connect.Request[chainpb.SubscribeRequest]) (*connect.Response[chainpb.SubscribeResponse], error) {
	if h.sub == nil {
		return h.UnimplementedChainServiceHandler.Subscribe(ctx, req)
	}
	id, err := h.sub.Subscribe(ctx, req.Msg.GetSubscriberDid(), req.Msg.GetPublisherDid(), req.Msg.GetPayloadDelivery())
	if err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&chainpb.SubscribeResponse{SubscriptionId: id}), nil
}

// Unsubscribe tears down a subscription this CM holds. Without a configured
// SubscriberService it reports CodeUnimplemented.
func (h *OperatorHandler) Unsubscribe(ctx context.Context, req *connect.Request[chainpb.UnsubscribeRequest]) (*connect.Response[chainpb.UnsubscribeResponse], error) {
	if h.sub == nil {
		return h.UnimplementedChainServiceHandler.Unsubscribe(ctx, req)
	}
	if err := h.sub.Unsubscribe(ctx, req.Msg.GetSubscriptionId()); err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&chainpb.UnsubscribeResponse{}), nil
}
