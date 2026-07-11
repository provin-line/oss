package chainmanager

import (
	"context"
	"errors"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
)

// Subscribe's AddImport LOCAL subject is now publisherDID (D-4 rename), NOT
// the remote subject: for inline this is unobservable (remote == local ==
// publisherDID already), so this pins it directly via fakeInfra.importedLocal.
func TestSubscribe_LocalSubjectIsPublisherDID_Inline(t *testing.T) {
	inf, peer := &fakeInfra{}, defaultPeer()
	svc, _ := subSvc(inf, peer, publicGuard())
	if _, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, "inline"); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if len(inf.importedLocal) != 1 || inf.importedLocal[0] != pubPipeline {
		t.Errorf("AddImport local subject = %v, want [%s]", inf.importedLocal, pubPipeline)
	}
}

// The by-reference case is where the rename is OBSERVABLE: the remote subject
// the publisher exported is byref.<publisherDID>, but AddImport's local
// subject must still be the plain publisherDID — so consuming-loop config
// (ingress-subject = publisherDID) never has to know the mode.
func TestSubscribe_LocalSubjectIsPublisherDID_ByReference(t *testing.T) {
	inf := &fakeInfra{}
	peer := defaultPeer()
	byrefRemote := ByReferenceSubjectPrefix + pubPipeline
	peer.connInfo = map[string]string{"subject": byrefRemote}
	svc, subs := subSvc(inf, peer, publicGuard())

	id, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, "by-reference")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if len(inf.imported) != 1 || inf.imported[0] != byrefRemote {
		t.Fatalf("AddImport remote subject = %v, want [%s]", inf.imported, byrefRemote)
	}
	if len(inf.importedLocal) != 1 || inf.importedLocal[0] != pubPipeline {
		t.Fatalf("AddImport local subject = %v, want [%s] (rename, not the remote byref subject)", inf.importedLocal, pubPipeline)
	}
	got, _ := subs.Get(id)
	if got.PayloadDelivery != "by-reference" {
		t.Errorf("stored mode = %q, want by-reference", got.PayloadDelivery)
	}
}

// --- Mixed-mode invariant, subscriber side (authoritative, D-4) ------------

// Subscribe rejects a second subscription to the SAME publisher regardless of
// the requested mode — mode is per-subscription immutable; changing it means
// Unsubscribe then re-Subscribe.
func TestSubscribe_DuplicatePublisher_Rejected(t *testing.T) {
	inf, peer := &fakeInfra{}, defaultPeer()
	svc, _ := subSvc(inf, peer, publicGuard())
	if _, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, "inline"); err != nil {
		t.Fatalf("first Subscribe: %v", err)
	}
	_, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, "by-reference")
	if !errors.Is(err, ErrDuplicateSubscription) {
		t.Fatalf("second Subscribe (different mode) err = %v, want ErrDuplicateSubscription", err)
	}
	// same-mode re-Subscribe is ALSO rejected (any existing subscription blocks).
	_, err = svc.Subscribe(context.Background(), subOwner, pubPipeline, "inline")
	if !errors.Is(err, ErrDuplicateSubscription) {
		t.Fatalf("second Subscribe (same mode) err = %v, want ErrDuplicateSubscription", err)
	}
	// No wasted remote round-trip: only the first, successful registration.
	if peer.registered != 1 {
		t.Errorf("remote RegisterSubscription calls = %d, want 1 (duplicate rejected locally)", peer.registered)
	}
}

// After Unsubscribe, re-Subscribing to the same publisher is allowed again
// (mode change = Unsubscribe → Subscribe, the documented path).
func TestSubscribe_AfterUnsubscribe_CanResubscribeDifferentMode(t *testing.T) {
	inf, peer := &fakeInfra{}, defaultPeer()
	svc, _ := subSvc(inf, peer, publicGuard())
	id, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, "inline")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Unsubscribe(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, "by-reference"); err != nil {
		t.Fatalf("re-Subscribe after Unsubscribe: %v, want success", err)
	}
}

// The duplicate check MUST hold under concurrency: the unlocked pre-RPC check
// is a fast-fail only, and a concurrent Subscribe that commits between that
// check and the lock must be caught by the locked re-check — the loser
// compensates its already-registered remote side and wires nothing locally
// (multi-agent-review convergent finding, 2026-07-12). Deterministic replay:
// the fake peer's onRegister hook plays the concurrent winner by persisting a
// competing subscription right after the remote side-effect commits.
func TestSubscribe_ConcurrentDuplicate_RecheckUnderLock(t *testing.T) {
	inf, peer := &fakeInfra{}, defaultPeer()
	svc, subs := subSvc(inf, peer, publicGuard())
	peer.onRegister = func() {
		if err := subs.Save(&store.Subscription{
			ID:            "winner",
			SubscriberDID: subOwner,
			PublisherDID:  pubPipeline,
			Direction:     "subscriber",
		}); err != nil {
			t.Fatalf("save competing subscription: %v", err)
		}
	}

	_, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, "inline")
	if !errors.Is(err, ErrDuplicateSubscription) {
		t.Fatalf("Subscribe err = %v, want ErrDuplicateSubscription (locked re-check)", err)
	}
	// The loser's remote registration is compensated…
	if len(peer.disconnected) != 1 || peer.disconnected[0] != peer.remoteID {
		t.Errorf("compensating Disconnect calls = %v, want [%s]", peer.disconnected, peer.remoteID)
	}
	// …nothing is wired locally, and only the winner's record remains.
	if len(inf.imported) != 0 {
		t.Errorf("AddImport calls = %v, want none (loser must not wire an import)", inf.imported)
	}
	all, _ := subs.List()
	if len(all) != 1 || all[0].ID != "winner" {
		t.Errorf("stored subscriptions = %+v, want exactly the concurrent winner", all)
	}
}

// The remote-supplied import subject is asserted against subjectForMode for
// the AGREED mode: a publisher answering with a foreign subject must not be
// able to steer the subscriber's import (it would be renamed onto
// publisherDID and consumed as if it were the publisher's output).
func TestSubscribe_RemoteSubjectMismatch_Rejected(t *testing.T) {
	inf, peer := &fakeInfra{}, defaultPeer()
	// Publisher agrees to inline but hands back a subject that is neither the
	// plain DID nor the byref form of it.
	peer.connInfo = map[string]string{"subject": "did:dplaax:reg:org:evil:pipeline:other"}
	svc, subs := subSvc(inf, peer, publicGuard())

	_, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, "inline")
	if !errors.Is(err, ErrRemotePeer) {
		t.Fatalf("Subscribe err = %v, want ErrRemotePeer (import-subject mismatch)", err)
	}
	if len(peer.disconnected) != 1 {
		t.Errorf("compensating Disconnect calls = %d, want 1", len(peer.disconnected))
	}
	if len(inf.imported) != 0 {
		t.Errorf("AddImport calls = %v, want none", inf.imported)
	}
	if all, _ := subs.List(); len(all) != 0 {
		t.Errorf("stored subscriptions = %d, want 0", len(all))
	}
}
