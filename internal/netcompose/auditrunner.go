package netcompose

import (
	"context"
	"fmt"

	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/resolver"
	"github.com/provin-line/oss/vc"
	"github.com/provin-line/oss/vc/chainwalk"
)

// localChainResolver adapts the node's local *vcresolver.Service to chainwalk's
// CredentialResolver: it resolves previousCredential links over the LOCAL store (the
// substrate slice-17g filled in-process), so the audit assembly does no network fetch.
type localChainResolver struct{ svc *vcresolver.Service }

func (l localChainResolver) ResolveCredential(ctx context.Context, contentAddress string) (*vc.PipelinePassCredential, error) {
	return l.svc.ResolveVC(ctx, contentAddress)
}

// BuildAuditRunner constructs the async audit runner, or returns (nil, nil) when the node
// has no consuming loop (no consumed heads register, so there is nothing to audit). The
// audit chainwalk's MaxDepth equals the batch resolver's max-depth (D-17h-4): neither
// component rejects a chain the other accepts.
func BuildAuditRunner(
	queue auditor.AuditQueue,
	status auditor.StatusStore,
	receipts auditor.ReceiptReader,
	vcSvc *vcresolver.Service,
	pool auditor.PoolLiveness,
	didResolver resolver.Resolver,
	schemaRes vc.SchemaResolver,
	pipeCfg *pipelineconfig.Config,
) (*auditor.Runner, error) {
	if !pipeCfg.HasConsumingLoop() {
		return nil, nil
	}
	// The async re-verification applies the same schema content-hash discipline
	// as the ingress verifier, so a chain that was verified on the consume path
	// re-verifies identically out of band.
	var vopts []vc.VerifierOption
	if schemaRes != nil {
		vopts = append(vopts, vc.WithSchemaResolver(schemaRes))
	}
	verifier := vc.NewVerifier(didResolver, ed25519.Verifier{}, vopts...)
	cv, err := chainwalk.New(localChainResolver{svc: vcSvc}, verifier, chainwalk.WithMaxDepth(pipeCfg.BatchResolver.MaxDepth))
	if err != nil {
		return nil, fmt.Errorf("standalone: audit chain verifier: %w", err)
	}
	// WithSourceCommitment enables emit-locus consumed-set self-audit (slice-17o): for an
	// aggregate head with a local receipt, the runner gathers the consumed sources from the
	// local store and records a distinct source-commitment verdict via the same verifier.
	return auditor.New(queue, vcSvc, cv, status, pool, auditor.Config{
		Interval:    pipeCfg.AuditRunner.Interval,
		BatchSize:   pipeCfg.AuditRunner.BatchSize,
		MaxAttempts: pipeCfg.AuditRunner.MaxAttempts,
	}, auditor.WithSourceCommitment(receipts, verifier))
}
