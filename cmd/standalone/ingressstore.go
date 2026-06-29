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
	StoreVC(ctx context.Context, credential []byte, upstreamEndpoint string, assemblyDepth int) (string, error)
}

// auditRegistrar registers a consumed head's content address for async audit (slice-17h).
// cmd/standalone owns this local interface; *auditor.MemQueue satisfies it.
type auditRegistrar interface {
	Add(headHash string) error
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
	// audit registers the stored head for async audit (slice-17h, D-17h-2). When nil, no
	// registration happens (a node without the audit runner — e.g. a unit test that does not
	// exercise the audit path).
	audit auditRegistrar
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
	// A consumed ingress credential is directly received — assembly depth 0; its
	// missing predecessor enqueues at depth 1.
	headHash, err := s.store.StoreVC(ctx, b, upstreamEndpoint, 0)
	if err != nil {
		return fmt.Errorf("ingressstore: store vc: %w", err)
	}
	// Register the consumed head for async audit (slice-17h, D-17h-2). Fail-closed, like the
	// store above: losing the registration would drop this credential from the audit trail,
	// the failure 17f's "never continue without the audit trail" contract guards against.
	if s.audit != nil {
		if err := s.audit.Add(headHash); err != nil {
			return fmt.Errorf("ingressstore: register audit head: %w", err)
		}
	}
	return nil
}
