package runtime

import (
	"context"
	"fmt"

	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/vc"
)

// StoredHead identifies one locally stored credential both ways the audit
// substrate needs: the BODY content address (the audit queue's key today)
// and the WIRE VARIANT id (what a future wire audit registration — see
// AuditService.RegisterAuditHead — must present for admission). It mirrors
// network/pkg/services/vcresolver.StoreVCResult so this package stays
// network-agnostic (network/ and pipeline/ never import each other, AGENTS.md
// rule 2); cmd/standalone's ingressStoreAdapter maps both fields from the
// real *vcresolver.Service.
//
// StoredHead is deliberately NOT the same type as StoredCredential
// (publishingsigner.go), even though the two share this exact shape today.
// StoredCredential is what a REMOTE publish (CredentialPublisher, this
// node's own signed output) round-trips against; StoredHead is what a LOCAL
// store call (IngressStorer, any consumed-or-emitted head, not necessarily
// signed by this node) hands to the audit substrate (AuditRegistrar). Their
// callers, lifecycles, and evolution paths differ — collapsing them would
// couple the publish round-trip check to the audit-registration seam for no
// reason beyond a coincidental field match.
type StoredHead struct {
	// BodyAddress is the server-recomputed content address ("sha256:<hex>") —
	// the audit queue's key today.
	BodyAddress string
	// WireVariantID names the exact wire bytes the store admitted
	// ("wire:v1:jcs-rfc8785:sha256:<hex>") — not yet consumed by the audit
	// queue (body-keyed, see StoreIngressVC's doc), carried here so a future
	// wire audit registration can present it.
	WireVariantID string
}

// IngressStorer is the StoreVC seam the consuming loops' ingress store writes
// through. It returns the full StoredHead rather than
// network/pkg/services/vcresolver.StoreVCResult directly — this package stays
// network-agnostic (network/ and pipeline/ never import each other, AGENTS.md
// rule 2). cmd/standalone adapts *vcresolver.Service to this interface.
type IngressStorer interface {
	StoreVC(ctx context.Context, credential []byte, upstreamEndpoint string, assemblyDepth int) (StoredHead, error)
}

// AuditRegistrar registers a consumed head for async audit (slice-17h). cmd/standalone
// owns this local interface; an adapter over *auditor.MemQueue (or the file-backed
// audit queue) satisfies it.
type AuditRegistrar interface {
	Add(head StoredHead) error
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
	head, err := s.store.StoreVC(ctx, b, upstreamEndpoint, 0)
	if err != nil {
		return fmt.Errorf("ingressstore: store vc: %w", err)
	}
	// Register the consumed head for async audit (slice-17h, D-17h-2). Fail-closed, like the
	// store above: losing the registration would drop this credential from the audit trail,
	// the failure 17f's "never continue without the audit trail" contract guards against.
	//
	// AuditRegistrar.Add receives the full StoredHead now (task-3 seam widening), but the
	// audit queue itself is STILL body-keyed today — that is exactly what P0-1 invariants 6
	// and 12 rule out, a verdict must name the variant it evaluated. Slice B carries that on
	// the queue's own side; this widening only ensures the variant id is no longer dropped
	// on the way there, so a future wire adapter (AuditService.RegisterAuditHead) can recover
	// it — it does not itself change what the in-process queue keys by.
	if s.audit != nil {
		if err := s.audit.Add(head); err != nil {
			return fmt.Errorf("ingressstore: register audit head: %w", err)
		}
	}
	return nil
}
