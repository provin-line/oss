package inputcapture_test

import (
	"context"
	"errors"
	"testing"

	"github.com/provin-line/oss/appraisal/inputcapture"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/resolver"
)

type changingResolver struct {
	docs []*did.DIDDocument
	n    int
}

func (r *changingResolver) Resolve(context.Context, string) (*did.DIDDocument, error) {
	if len(r.docs) == 0 {
		return nil, resolver.ErrNotFound
	}
	doc := r.docs[r.n%len(r.docs)]
	r.n++
	return doc, nil
}

func TestCaptureRejectsSameNameChangingMidEvaluation(t *testing.T) {
	doc1 := did.New(did.DocumentFields{ID: "did:dplaax:example.test:org:a"})
	doc2 := did.New(did.DocumentFields{ID: "did:dplaax:example.test:org:b"})
	r := inputcapture.DIDResolver{Next: &changingResolver{docs: []*did.DIDDocument{doc1, doc2}}}
	ctx, session := (inputcapture.Recorder{}).Start(context.Background())
	if _, err := r.Resolve(ctx, "did:dplaax:example.test:org:a"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(ctx, "did:dplaax:example.test:org:a"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Digests(); !errors.Is(err, inputcapture.ErrSnapshotConflict) {
		t.Fatalf("Digests error=%v", err)
	}
}

func TestCaptureIsContextIsolated(t *testing.T) {
	doc := did.New(did.DocumentFields{ID: "did:dplaax:example.test:org:a"})
	r := inputcapture.DIDResolver{Next: &changingResolver{docs: []*did.DIDDocument{doc}}}
	ctx1, s1 := (inputcapture.Recorder{}).Start(context.Background())
	_, s2 := (inputcapture.Recorder{}).Start(context.Background())
	if _, err := r.Resolve(ctx1, doc.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := s1.Digests(); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Digests(); !errors.Is(err, inputcapture.ErrNoSnapshots) {
		t.Fatalf("second session error=%v", err)
	}
}
