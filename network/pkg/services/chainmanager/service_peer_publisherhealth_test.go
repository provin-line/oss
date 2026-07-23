package chainmanager

import (
	"context"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/chainmanager/emithealth"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store/memstore"
)

// publisherGatedServing builds a payload-serving Service with an injected
// per-publisher health lookup that answers `state`/`advertiseWithoutReports`
// for EVERY publisherDID (the per-publisher tests below pin one, pubPipeline;
// TestPeer_PublisherInfo_PublisherHealthGate_PerPublisher below proves the
// lookup is genuinely keyed by the argument).
func publisherGatedServing(t *testing.T, state emithealth.HealthState, advertiseWithoutReports bool) *Service {
	t.Helper()
	subs := memstore.NewSubscriptionStore()
	allows := memstore.NewAllowListStore()
	if err := allows.Save(pubPipeline, []store.AllowRule{{Pattern: "did:dplaax:*:org:sub"}}); err != nil {
		t.Fatal(err)
	}
	return New(subs, allows,
		WithInfraOperator(&fakeInfra{}),
		WithPayloadServing(),
		WithPublisherHealth(func(string) emithealth.HealthState { return state }, advertiseWithoutReports),
	)
}

// Every HealthState, crossed with both advertiseWithoutReports settings,
// drives the by-reference advertisement decision exactly per
// WithPublisherHealth's documented table.
func TestPeer_PublisherInfo_PublisherHealthGate(t *testing.T) {
	cases := []struct {
		name                    string
		state                   emithealth.HealthState
		advertiseWithoutReports bool
		wantByRef               bool
	}{
		{"healthy reported advertises (advertiseWithoutReports=false)", emithealth.HealthyReported, false, true},
		{"healthy reported advertises (advertiseWithoutReports=true)", emithealth.HealthyReported, true, true},
		{"unhealthy reported degrades (advertiseWithoutReports=false)", emithealth.UnhealthyReported, false, false},
		{"unhealthy reported degrades (advertiseWithoutReports=true)", emithealth.UnhealthyReported, true, false},
		{"expired degrades (advertiseWithoutReports=false)", emithealth.Expired, false, false},
		{"expired degrades (advertiseWithoutReports=true)", emithealth.Expired, true, false},
		{"never reported degrades when advertiseWithoutReports=false", emithealth.NeverReported, false, false},
		{"never reported advertises when advertiseWithoutReports=true", emithealth.NeverReported, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc := publisherGatedServing(t, c.state, c.advertiseWithoutReports)
			_, modes, err := svc.PublisherInfo(context.Background(), pubPipeline, subOwner)
			if err != nil {
				t.Fatalf("PublisherInfo: %v", err)
			}
			if got := offersByReference(modes); got != c.wantByRef {
				t.Errorf("by-reference advertised = %v, want %v", got, c.wantByRef)
			}
		})
	}
}

// The gate also gates ENFORCEMENT (RegisterSubscription's negotiation), same
// as the global WithByReferenceHealth gate already proves.
func TestPeer_RegisterSubscription_PublisherHealthGate(t *testing.T) {
	t.Run("unhealthy reported refuses by-reference", func(t *testing.T) {
		svc := publisherGatedServing(t, emithealth.UnhealthyReported, false)
		if _, err := svc.RegisterSubscription(context.Background(), subOwner, pubPipeline, "by-reference"); err == nil {
			t.Error("unhealthy reported: by-reference registration must be refused")
		}
		// inline is unaffected by the by-reference gate.
		if _, err := svc.RegisterSubscription(context.Background(), subOwner, pubPipeline, "inline"); err != nil {
			t.Errorf("unhealthy reported: inline registration must still succeed, got %v", err)
		}
	})
	t.Run("healthy reported allows by-reference", func(t *testing.T) {
		svc := publisherGatedServing(t, emithealth.HealthyReported, false)
		if _, err := svc.RegisterSubscription(context.Background(), subOwner, pubPipeline, "by-reference"); err != nil {
			t.Errorf("healthy reported: by-reference registration must succeed, got %v", err)
		}
	})
}

// The lookup is genuinely PER-PUBLISHER: a different publisherDID than the
// one the lookup answers "healthy" for gets its OWN, independent decision —
// proving offeredPayloadModes threads the actual publisherDID argument
// through rather than reusing one node-global flag (the design point that
// distinguishes WithPublisherHealth from WithByReferenceHealth).
func TestPeer_PublisherInfo_PublisherHealthGate_PerPublisher(t *testing.T) {
	subs := memstore.NewSubscriptionStore()
	allows := memstore.NewAllowListStore()
	otherPub := "did:dplaax:reg:org:acme:pipeline:p2"
	for _, pid := range []string{pubPipeline, otherPub} {
		if err := allows.Save(pid, []store.AllowRule{{Pattern: "did:dplaax:*:org:sub"}}); err != nil {
			t.Fatal(err)
		}
	}
	svc := New(subs, allows,
		WithInfraOperator(&fakeInfra{}),
		WithPayloadServing(),
		WithPublisherHealth(func(publisherDID string) emithealth.HealthState {
			if publisherDID == pubPipeline {
				return emithealth.HealthyReported
			}
			return emithealth.UnhealthyReported
		}, false),
	)

	_, modes, err := svc.PublisherInfo(context.Background(), pubPipeline, subOwner)
	if err != nil {
		t.Fatalf("PublisherInfo(pubPipeline): %v", err)
	}
	if !offersByReference(modes) {
		t.Error("pubPipeline (healthy) must advertise by-reference")
	}

	_, modes, err = svc.PublisherInfo(context.Background(), otherPub, subOwner)
	if err != nil {
		t.Fatalf("PublisherInfo(otherPub): %v", err)
	}
	if offersByReference(modes) {
		t.Error("otherPub (unhealthy) must NOT advertise by-reference")
	}
}

// Composing WithByReferenceHealth (node-global; no current binary wires it)
// and WithPublisherHealth (per-publisher, cmd/network report-mode) on the SAME
// Service is a composition-root error — New panics rather than silently
// picking one model, regardless of option order.
func TestNew_BothHealthGates_Panics(t *testing.T) {
	healthyLookup := func(string) emithealth.HealthState { return emithealth.HealthyReported }

	t.Run("byRef then publisher", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("New must panic when both gates are configured")
			}
		}()
		New(memstore.NewSubscriptionStore(), memstore.NewAllowListStore(),
			WithByReferenceHealth(func() bool { return true }),
			WithPublisherHealth(healthyLookup, false),
		)
	})
	t.Run("publisher then byRef", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("New must panic when both gates are configured, regardless of option order")
			}
		}()
		New(memstore.NewSubscriptionStore(), memstore.NewAllowListStore(),
			WithPublisherHealth(healthyLookup, false),
			WithByReferenceHealth(func() bool { return true }),
		)
	})
}

// WithPublisherHealth(nil, ...) panics at option-apply time (inside New),
// never silently disabling the gate.
func TestWithPublisherHealth_NilLookup_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("New must panic when WithPublisherHealth is given a nil lookup")
		}
	}()
	New(memstore.NewSubscriptionStore(), memstore.NewAllowListStore(), WithPublisherHealth(nil, false))
}
