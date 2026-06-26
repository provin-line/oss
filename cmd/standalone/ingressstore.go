package main

import (
	"context"
	"fmt"

	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/vc"
)

// ingressStorer is the StoreVC seam the consuming loops' ingress store writes through —
// satisfied by *vcresolver.Service. cmd/standalone owns this local interface so the data
// plane depends on the capability, not the concrete service.
type ingressStorer interface {
	StoreVC(ctx context.Context, credential []byte, upstreamEndpoint string) (string, error)
}

// Compile-time assertion: serviceIngressStore satisfies contract.IngressVCStore.
var _ contract.IngressVCStore = (*serviceIngressStore)(nil)

// serviceIngressStore implements contract.IngressVCStore over an ingressStorer
// (the node's local *vcresolver.Service). StoreIngressVC marshals the credential
// using its JCS-canonical MarshalJSON bytes (D-17f-3) and calls StoreVC, which
// stores the credential at its content address and enqueues any missing predecessor
// into the unresolved pool (D-17f-1).
type serviceIngressStore struct {
	store ingressStorer
}

// StoreIngressVC implements contract.IngressVCStore. It marshals cred using
// MarshalJSON (canonical bytes, D-17f-3) and delegates to StoreVC. StoreVC
// is fail-closed: a malformed previousCredential link returns an error
// (D-17f-6), which the consuming loop treats as StatusErrored.
func (s *serviceIngressStore) StoreIngressVC(ctx context.Context, cred *vc.PipelinePassCredential, upstreamEndpoint string) error {
	b, err := cred.MarshalJSON()
	if err != nil {
		return fmt.Errorf("ingressstore: marshal credential: %w", err)
	}
	if _, err := s.store.StoreVC(ctx, b, upstreamEndpoint); err != nil {
		return fmt.Errorf("ingressstore: store vc: %w", err)
	}
	return nil
}
