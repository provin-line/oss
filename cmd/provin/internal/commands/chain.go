package commands

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
)

// ChainSubscribeConfig carries `provin chain subscribe`'s inputs beyond the
// global environment. Subscriber and Publisher are required (checked by the
// caller). Delivery is the requested payload-delivery mode; empty means
// "omitted" — the wire's own conservative default (by-reference), which this
// command passes through rather than inventing a client-side default.
type ChainSubscribeConfig struct {
	Subscriber string
	Publisher  string
	Delivery   string
}

// ChainSubscribe establishes a subscription and prints the assigned id along
// with the delivery mode that was REQUESTED. SubscribeResponse carries only
// the id — the server does not echo back a confirmed mode — so the output
// must not claim the mode as server-confirmed; an omitted/empty Delivery is
// labeled "by-reference (protocol default)" to make the empty-wire-value
// resolution visible to the operator.
func ChainSubscribe(ctx context.Context, env Env, cfg ChainSubscribeConfig) error {
	c, err := env.chainClient()
	if err != nil {
		return err
	}
	res, err := c.Subscribe(ctx, connect.NewRequest(&chainpb.SubscribeRequest{
		SubscriberDid:   cfg.Subscriber,
		PublisherDid:    cfg.Publisher,
		PayloadDelivery: cfg.Delivery,
	}))
	if err != nil {
		return fmt.Errorf("chain subscribe: %w", err)
	}
	requested := cfg.Delivery
	if requested == "" {
		requested = "by-reference (protocol default)"
	}
	fmt.Fprintf(env.out(), "subscribed %s (delivery requested: %s)\n", res.Msg.GetSubscriptionId(), requested)
	return nil
}

// ChainSetAllowConfig carries `provin chain set-allow`'s inputs beyond the
// global environment. Pipeline is required (checked by the caller). Exactly
// one of "len(Patterns) > 0" or "Clear" must hold — UpdateAllowList is a
// full-replacement RPC, so an empty rule set (deny-all) must be an explicit
// operator decision (Clear), never the side effect of a typo that dropped
// every --pattern.
type ChainSetAllowConfig struct {
	Pipeline string
	Patterns []string
	Clear    bool
}

// ChainSetAllow REPLACES cfg.Pipeline's entire allow-list with cfg.Patterns
// (or with zero rules when cfg.Clear is set) and prints the resulting rule
// count so a fat-fingered short replacement of a long list is visible
// immediately. Clear+Patterns together, and neither, are local usage errors
// — no RPC is attempted for either.
func ChainSetAllow(ctx context.Context, env Env, cfg ChainSetAllowConfig) error {
	if cfg.Clear && len(cfg.Patterns) > 0 {
		return fmt.Errorf("chain set-allow: --clear and --pattern are mutually exclusive")
	}
	if !cfg.Clear && len(cfg.Patterns) == 0 {
		return fmt.Errorf("chain set-allow: at least one --pattern is required, or pass --clear to REPLACE the allow-list with zero rules (deny-all) as an explicit decision")
	}
	c, err := env.chainClient()
	if err != nil {
		return err
	}
	rules := make([]*chainpb.AllowRule, len(cfg.Patterns))
	for i, p := range cfg.Patterns {
		rules[i] = &chainpb.AllowRule{Pattern: p}
	}
	if _, err := c.UpdateAllowList(ctx, connect.NewRequest(&chainpb.UpdateAllowListRequest{
		PipelineDid: cfg.Pipeline,
		Rules:       rules,
	})); err != nil {
		return fmt.Errorf("chain set-allow: %w", err)
	}
	fmt.Fprintf(env.out(), "allow-list for %s replaced (%d rules)\n", cfg.Pipeline, len(cfg.Patterns))
	return nil
}
