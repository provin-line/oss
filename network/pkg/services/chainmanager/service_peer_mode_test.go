package chainmanager

import (
	"context"
	"errors"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store/memstore"
)

// svcServing builds a Service admitting pubPipeline → subOwner/subTwoOwner with
// payload serving enabled (so by-reference registrations are actually offered —
// see offeredPayloadModes).
func svcServing(t *testing.T, inf *fakeInfra) *Service {
	t.Helper()
	subs := memstore.NewSubscriptionStore()
	allows := memstore.NewAllowListStore()
	if err := allows.Save(pubPipeline, []store.AllowRule{
		{Pattern: "did:dplaax:*:org:sub"},
		{Pattern: "did:dplaax:*:org:sub2"},
	}); err != nil {
		t.Fatal(err)
	}
	return New(subs, allows, WithInfraOperator(inf), WithPayloadServing())
}

const byrefPubSubject = ByReferenceSubjectPrefix + pubPipeline

// By-reference registration exports the byref.-prefixed subject, not the
// plain publisher DID (D-2/D-3).
func TestPeer_RegisterSubscription_ByReference_ExportsPrefixedSubject(t *testing.T) {
	inf := &fakeInfra{}
	svc := svcServing(t, inf)
	sub, err := svc.RegisterSubscription(context.Background(), subOwner, pubPipeline, "by-reference")
	if err != nil {
		t.Fatalf("RegisterSubscription: %v", err)
	}
	if sub.ConnectionInfo["subject"] != byrefPubSubject {
		t.Errorf("connection_info[subject] = %q, want %q", sub.ConnectionInfo["subject"], byrefPubSubject)
	}
	if len(inf.added) != 1 || inf.added[0] != byrefPubSubject {
		t.Errorf("AddExport calls = %v, want [%s]", inf.added, byrefPubSubject)
	}
}

// Regression (W5): an inline registration still exports the PLAIN publisher
// DID, unaffected by the by-reference prefix scheme.
func TestPeer_RegisterSubscription_Inline_StillExportsPlainSubject(t *testing.T) {
	inf := &fakeInfra{}
	svc := svcServing(t, inf)
	sub, err := svc.RegisterSubscription(context.Background(), subOwner, pubPipeline, "inline")
	if err != nil {
		t.Fatalf("RegisterSubscription: %v", err)
	}
	if sub.ConnectionInfo["subject"] != pubPipeline {
		t.Errorf("connection_info[subject] = %q, want the plain publisher DID %q", sub.ConnectionInfo["subject"], pubPipeline)
	}
	if len(inf.added) != 1 || inf.added[0] != pubPipeline {
		t.Errorf("AddExport calls = %v, want [%s]", inf.added, pubPipeline)
	}
}

// Ref-counting is keyed on the EXPORTED SUBJECT, not the publisher DID: an
// inline and a by-reference registration for the SAME publisher export
// DIFFERENT subjects and must ref-count independently — disconnecting one
// must not tear down the other's export (D-3).
func TestPeer_InlineAndByReference_CoexistIndependentRefcount(t *testing.T) {
	inf := &fakeInfra{}
	svc := svcServing(t, inf)

	inlineSub, err := svc.RegisterSubscription(context.Background(), subOwner, pubPipeline, "inline")
	if err != nil {
		t.Fatalf("RegisterSubscription(inline): %v", err)
	}
	byrefSub, err := svc.RegisterSubscription(context.Background(), "did:dplaax:reg:org:sub2", pubPipeline, "by-reference")
	if err != nil {
		t.Fatalf("RegisterSubscription(by-reference): %v", err)
	}
	if len(inf.added) != 2 {
		t.Fatalf("AddExport calls = %v, want 2 independent exports", inf.added)
	}

	// Disconnecting the inline subscription must remove ONLY the plain
	// subject export — the by-reference export must survive.
	if err := svc.Disconnect(context.Background(), inlineSub.ID, subOwner); err != nil {
		t.Fatalf("Disconnect(inline): %v", err)
	}
	if len(inf.removed) != 1 || inf.removed[0] != pubPipeline {
		t.Fatalf("removed = %v, want [%s] only", inf.removed, pubPipeline)
	}

	// The by-reference export is untouched; disconnecting it now removes it.
	if err := svc.Disconnect(context.Background(), byrefSub.ID, "did:dplaax:reg:org:sub2"); err != nil {
		t.Fatalf("Disconnect(by-reference): %v", err)
	}
	if len(inf.removed) != 2 || inf.removed[1] != byrefPubSubject {
		t.Fatalf("removed = %v, want second entry %s", inf.removed, byrefPubSubject)
	}
}

// Two subscribers registering the SAME mode for the SAME publisher share one
// export SUBJECT (ref-count > 1, idempotent AddExport at the infra layer —
// the domain calls AddExport for every registration; the real nats.Operator
// and noop.Operator are both idempotent no-ops on a repeat subject): the
// first Disconnect must NOT remove it.
func TestPeer_ByReference_SiblingSameModeSharesExport(t *testing.T) {
	inf := &fakeInfra{}
	svc := svcServing(t, inf)
	s1, err := svc.RegisterSubscription(context.Background(), subOwner, pubPipeline, "by-reference")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterSubscription(context.Background(), "did:dplaax:reg:org:sub2", pubPipeline, "by-reference"); err != nil {
		t.Fatal(err)
	}
	for _, s := range inf.added {
		if s != byrefPubSubject {
			t.Fatalf("AddExport calls = %v, want both calls to share subject %q", inf.added, byrefPubSubject)
		}
	}
	if err := svc.Disconnect(context.Background(), s1.ID, subOwner); err != nil {
		t.Fatal(err)
	}
	if len(inf.removed) != 0 {
		t.Errorf("sibling remains: RemoveExport must not fire, got %v", inf.removed)
	}
}

// Disconnect tears down the subject STORED at ConnectionInfo["subject"] —
// never recomputed from PayloadDelivery/subjectForMode. A legacy record
// whose stored mode is empty (the old by-reference default) but whose ACTUAL
// export was the plain subject (pre-dual-emit posture) must still have the
// PLAIN export removed — not a byref.-prefixed subject that was never
// exported (D-3 migration: the residual "legacy export leak" this closes).
func TestPeer_Disconnect_LegacyEmptyMode_RemovesStoredPlainSubject(t *testing.T) {
	inf := &fakeInfra{}
	svc, subs := svcWith(t, inf)
	legacy := &store.Subscription{
		ID:              "legacy-empty",
		SubscriberDID:   subOwner,
		PublisherDID:    pubPipeline,
		PayloadDelivery: "",                                        // legacy default meaning "by-reference" per store doc
		ConnectionInfo:  map[string]string{"subject": pubPipeline}, // but actually exported PLAIN
		Direction:       directionPublisher,
	}
	if err := subs.Save(legacy); err != nil {
		t.Fatal(err)
	}
	if err := svc.Disconnect(context.Background(), legacy.ID, subOwner); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if len(inf.removed) != 1 || inf.removed[0] != pubPipeline {
		t.Fatalf("removed = %v, want [%s] (the ACTUALLY exported plain subject)", inf.removed, pubPipeline)
	}
}

// Same migration proof for a legacy record with an EXPLICIT "by-reference"
// PayloadDelivery but whose ConnectionInfo still names the plain subject
// (pre-mode-application posture — every record before this slice exported
// plain regardless of agreed mode).
func TestPeer_Disconnect_LegacyExplicitByReference_RemovesStoredPlainSubject(t *testing.T) {
	inf := &fakeInfra{}
	svc, subs := svcWith(t, inf)
	legacy := &store.Subscription{
		ID:              "legacy-byref",
		SubscriberDID:   subOwner,
		PublisherDID:    pubPipeline,
		PayloadDelivery: "by-reference",
		ConnectionInfo:  map[string]string{"subject": pubPipeline},
		Direction:       directionPublisher,
	}
	if err := subs.Save(legacy); err != nil {
		t.Fatal(err)
	}
	if err := svc.Disconnect(context.Background(), legacy.ID, subOwner); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if len(inf.removed) != 1 || inf.removed[0] != pubPipeline {
		t.Fatalf("removed = %v, want [%s] (the ACTUALLY exported plain subject)", inf.removed, pubPipeline)
	}
}

// A publisher-direction record with NO ConnectionInfo["subject"] on record is
// an unrecoverable-by-guessing state: Disconnect must fail closed (typed
// error), never silently skip teardown or guess a subject to remove.
func TestPeer_Disconnect_MissingExportSubject_FailsClosed(t *testing.T) {
	inf := &fakeInfra{}
	svc, subs := svcWith(t, inf)
	broken := &store.Subscription{
		ID:            "broken",
		SubscriberDID: subOwner,
		PublisherDID:  pubPipeline,
		Direction:     directionPublisher,
		// ConnectionInfo intentionally nil/empty.
	}
	if err := subs.Save(broken); err != nil {
		t.Fatal(err)
	}
	err := svc.Disconnect(context.Background(), broken.ID, subOwner)
	if !errors.Is(err, ErrExportSubjectMissing) {
		t.Fatalf("err = %v, want ErrExportSubjectMissing", err)
	}
	if len(inf.removed) != 0 {
		t.Errorf("RemoveExport called despite missing ConnectionInfo[subject]: %v", inf.removed)
	}
	// Fail-closed means retryable / inspectable, not silently deleted.
	if got, _ := subs.Get(broken.ID); got == nil {
		t.Error("subscription was deleted despite the fail-closed Disconnect error")
	}
}

// --- Mixed-mode invariant, publisher side (defense-in-depth, D-4) ----------

// RegisterSubscription rejects a registration for the same (subscriber,
// publisher) pair that already has a subscription under a DIFFERENT mode.
func TestPeer_RegisterSubscription_MixedMode_Rejected(t *testing.T) {
	inf := &fakeInfra{}
	svc := svcServing(t, inf)
	if _, err := svc.RegisterSubscription(context.Background(), subOwner, pubPipeline, "inline"); err != nil {
		t.Fatal(err)
	}
	_, err := svc.RegisterSubscription(context.Background(), subOwner, pubPipeline, "by-reference")
	if !errors.Is(err, ErrMixedModeSubscription) {
		t.Fatalf("err = %v, want ErrMixedModeSubscription", err)
	}
	// No new export was created for the rejected registration.
	if len(inf.added) != 1 {
		t.Errorf("AddExport calls = %v, want exactly 1 (only the first, accepted registration)", inf.added)
	}
}

// The SAME mode registered twice for the same pair is NOT a mixed-mode
// violation (no invariant against exact-duplicate registrations pre-existed;
// this only guards against a MODE conflict).
func TestPeer_RegisterSubscription_SameModeTwice_NotMixedMode(t *testing.T) {
	inf := &fakeInfra{}
	svc := svcServing(t, inf)
	if _, err := svc.RegisterSubscription(context.Background(), subOwner, pubPipeline, "inline"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterSubscription(context.Background(), subOwner, pubPipeline, "inline"); err != nil {
		t.Fatalf("second same-mode registration: %v, want success", err)
	}
}

// Different SUBSCRIBERS requesting different modes to the SAME publisher must
// coexist freely — the mixed-mode invariant is scoped to one
// (subscriber, publisher) pair, not the publisher alone.
func TestPeer_RegisterSubscription_DifferentSubscribers_DifferentModes_Coexist(t *testing.T) {
	inf := &fakeInfra{}
	svc := svcServing(t, inf)
	if _, err := svc.RegisterSubscription(context.Background(), subOwner, pubPipeline, "inline"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterSubscription(context.Background(), "did:dplaax:reg:org:sub2", pubPipeline, "by-reference"); err != nil {
		t.Fatalf("different subscriber, different mode: %v, want success", err)
	}
	if len(inf.added) != 2 {
		t.Errorf("AddExport calls = %v, want 2 (independent subjects)", inf.added)
	}
}
