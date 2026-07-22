package runtime

import (
	"context"
	"fmt"

	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/vc"
)

// IngressStorer is the StoreVC seam the consuming loops' ingress store writes through —
// satisfied by *vcresolver.Service. cmd/standalone owns this local interface so the data
// plane depends on the capability, not the concrete service.
type IngressStorer interface {
	StoreVC(ctx context.Context, credential []byte, upstreamEndpoint string, assemblyDepth int) (vcresolver.StoreVCResult, error)
}

// AuditRegistrar registers a consumed head's content address for async audit (slice-17h).
// cmd/standalone owns this local interface; *auditor.MemQueue satisfies it.
type AuditRegistrar interface {
	Add(headHash string) error
}

// Compile-time assertion: serviceIngressStore satisfies contract.IngressVCStore.
var _ contract.IngressVCStore = (*serviceIngressStore)(nil)

// NewServiceIngressStore builds the composition-root contract.IngressVCStore
// over an ingress storer and an optional audit registrar (nil disables
// registration). Exported for composition-level tests that wire a sink or
// chained processor directly, outside Build's own assembly path — Build uses
// the equivalent unexported literal internally.
func NewServiceIngressStore(store IngressStorer, audit AuditRegistrar) contract.IngressVCStore {
	return &serviceIngressStore{store: store, audit: audit}
}

// serviceIngressStore implements contract.IngressVCStore over an IngressStorer
// (the node's local *vcresolver.Service). StoreIngressVC marshals the credential
// using its JCS-canonical MarshalJSON bytes (D-17f-3) and calls StoreVC, which
// stores the credential at its content address and enqueues any missing predecessor
// into the unresolved pool (D-17f-1).
type serviceIngressStore struct {
	store IngressStorer
	// audit registers the stored head for async audit (slice-17h, D-17h-2). When nil, no
	// registration happens (a node without the audit runner — e.g. a unit test that does not
	// exercise the audit path).
	audit AuditRegistrar
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
	res, err := s.store.StoreVC(ctx, b, upstreamEndpoint, 0)
	if err != nil {
		return fmt.Errorf("ingressstore: store vc: %w", err)
	}
	// Register the consumed head for async audit (slice-17h, D-17h-2). Fail-closed, like the
	// store above: losing the registration would drop this credential from the audit trail,
	// the failure 17f's "never continue without the audit trail" contract guards against.
	//
	// The head is registered by BODY address: the audit queue is body-keyed
	// today, which is exactly what P0-1 invariants 6 and 12 rule out — a verdict
	// must name the variant it evaluated. Slice B carries that; naming the
	// variant here would only move the mismatch, since nothing downstream can
	// yet receive it.
	if s.audit != nil {
		if err := s.audit.Add(res.BodyAddress); err != nil {
			return fmt.Errorf("ingressstore: register audit head: %w", err)
		}
	}
	return nil
}
