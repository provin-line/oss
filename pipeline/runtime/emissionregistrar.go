package runtime

import (
	"context"
	"fmt"

	"github.com/provin-line/oss/pipeline/source/aggregate"
	"github.com/provin-line/oss/vc"
)

// ReceiptWriter records the emit-time consumed-set receipt for an aggregate head (slice-17o):
// head content address → the consumed source content addresses, plus the registrant DID
// recorded alongside them (an audit-trail fact — see auditor.ReceiptStore.Put's doc).
// cmd/standalone owns this local interface (capability, not concrete);
// *auditor.MemReceiptStore satisfies it.
type ReceiptWriter interface {
	Put(headHash string, registrantDID string, consumedHashes []string) error
}

// emissionRegistrar is the composition-root aggregate.EmissionRegistrar (slice-17o D-17o-3/4):
// it commits an emitted aggregate credential to the node's audit substrate — the LOCAL store
// (so the audit runner resolves the head), the consumed-set receipt, the audit queue — and
// then, if a remote VC store is configured, publishes it there. Ordering is load-bearing:
// local self-audit registration happens BEFORE the remote publish and (upstream, in the
// aggregate runtime) before the NATS broadcast, so a credential is never externally visible
// without a local audit trail — the StoreIngressVC fail-closed precedent. This is why the
// aggregate path does NOT wrap its signer in publishingSigner (which would publish during
// signing, before the head hash even exists): the remote publish is reordered to here.
type emissionRegistrar struct {
	local     IngressStorer       // local StoreVC (returns the head content address)
	receipts  ReceiptWriter       // records head → consumed source hashes
	audit     AuditRegistrar      // enqueues the head for self-audit
	publisher CredentialPublisher // optional remote VC-store publish (nil => skip)
}

var _ aggregate.EmissionRegistrar = (*emissionRegistrar)(nil)

// NewEmissionRegistrar builds the composition-root aggregate.EmissionRegistrar
// directly. Exported for composition-level tests that register a real emitted
// credential for self-audit outside Build's own assembly path (which wires
// this internally whenever deps.Receipts and deps.AuditQueue are both set).
func NewEmissionRegistrar(local IngressStorer, receipts ReceiptWriter, audit AuditRegistrar, publisher CredentialPublisher) aggregate.EmissionRegistrar {
	return &emissionRegistrar{local: local, receipts: receipts, audit: audit, publisher: publisher}
}

// RegisterEmission persists the emitted credential locally, records the receipt, enqueues the
// head, and (if configured) publishes remotely — each fail-closed, in order.
func (r *emissionRegistrar) RegisterEmission(ctx context.Context, cred *vc.PipelinePassCredential, consumedHashes []string) error {
	b, err := cred.MarshalJSON()
	if err != nil {
		return fmt.Errorf("emissionRegistrar: marshal emitted credential: %w", err)
	}
	// An aggregate FirstDrop has no predecessor → no upstream hint, assembly depth 0. StoreVC
	// returns the server-recomputed StoredHead; its BodyAddress is the authoritative head hash
	// used as both the receipt key and the audit-queue key (so all three agree). Keying the
	// RECEIPT and QUEUE on the admitted variant instead is P0-1 slices B/C: it is the verdict
	// that has to name the exact bytes evaluated (invariants 6 and 12), and neither the receipt
	// store nor the audit queue can carry that yet — the WireVariantID travels through
	// r.audit.Add(head) regardless (task-3 seam widening), for a future wire adapter to use.
	head, err := r.local.StoreVC(ctx, b, "", 0)
	if err != nil {
		return fmt.Errorf("emissionRegistrar: local store emitted head: %w", err)
	}
	// cred.Issuer() is the Process DID this aggregate signs emitted heads under — the
	// identity this in-process path already holds, standing in for a wireauth-proven DID
	// (there is no wire caller here to prove one). Recorded as the receipt's registrant, an
	// audit-trail fact only (see auditor.ReceiptStore.Put's doc): this is NOT an ownership
	// check, and RegisterEmission never validates it against anything else.
	if err := r.receipts.Put(head.BodyAddress, cred.Issuer(), consumedHashes); err != nil {
		return fmt.Errorf("emissionRegistrar: write consumed-set receipt: %w", err)
	}
	if err := r.audit.Add(head); err != nil {
		return fmt.Errorf("emissionRegistrar: enqueue head for self-audit: %w", err)
	}
	if r.publisher != nil {
		if err := publishIssuedCredential(ctx, r.publisher, cred, ""); err != nil {
			return err
		}
	}
	return nil
}
