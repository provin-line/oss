package chainmanager

import (
	"context"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store/memstore"
)

// gatedServing builds a payload-serving Service with an injected by-reference
// health gate returning `healthy`.
func gatedServing(t *testing.T, healthy bool) *Service {
	t.Helper()
	subs := memstore.NewSubscriptionStore()
	allows := memstore.NewAllowListStore()
	if err := allows.Save(pubPipeline, []store.AllowRule{{Pattern: "did:dplaax:*:org:sub"}}); err != nil {
		t.Fatal(err)
	}
	return New(subs, allows,
		WithInfraOperator(&fakeInfra{}),
		WithPayloadServing(),
		WithByReferenceHealth(func() bool { return healthy }),
	)
}

func offersByReference(modes []string) bool {
	for _, m := range modes {
		if m == "by-reference" {
			return true
		}
	}
	return false
}

// A configured health gate suppresses by-reference advertisement when unhealthy,
// even on a payload-serving node — so a node whose stripped-publish emission is
// failing stops advertising a mode it can no longer honestly serve (D-5).
func TestPeer_PublisherInfo_ByReferenceHealthGate(t *testing.T) {
	for _, healthy := range []bool{true, false} {
		svc := gatedServing(t, healthy)
		_, modes, err := svc.PublisherInfo(context.Background(), pubPipeline, subOwner)
		if err != nil {
			t.Fatalf("healthy=%v PublisherInfo: %v", healthy, err)
		}
		if got := offersByReference(modes); got != healthy {
			t.Errorf("healthy=%v: by-reference advertised = %v, want %v", healthy, got, healthy)
		}
	}
}

// The gate also gates ENFORCEMENT: a by-reference registration is refused when
// the gate is unhealthy (the mode is no longer offered), while inline is
// unaffected. When healthy, by-reference registration still succeeds.
func TestPeer_RegisterSubscription_ByReferenceHealthGate(t *testing.T) {
	t.Run("unhealthy refuses by-reference", func(t *testing.T) {
		svc := gatedServing(t, false)
		if _, err := svc.RegisterSubscription(context.Background(), subOwner, pubPipeline, "by-reference"); err == nil {
			t.Error("unhealthy gate: by-reference registration must be refused")
		}
		// inline is unaffected by the by-reference gate.
		if _, err := svc.RegisterSubscription(context.Background(), subOwner, pubPipeline, "inline"); err != nil {
			t.Errorf("unhealthy gate: inline registration must still succeed, got %v", err)
		}
	})
	t.Run("healthy allows by-reference", func(t *testing.T) {
		svc := gatedServing(t, true)
		if _, err := svc.RegisterSubscription(context.Background(), subOwner, pubPipeline, "by-reference"); err != nil {
			t.Errorf("healthy gate: by-reference registration must succeed, got %v", err)
		}
	})
}
