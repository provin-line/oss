package main

import (
	"context"
	"fmt"

	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	"github.com/provin-line/oss/pipeline/provenance/chainwalk"
	"github.com/provin-line/oss/resolver"
	"github.com/provin-line/oss/vc"
)

// localChainResolver adapts the node's local *vcresolver.Service to chainwalk's
// CredentialResolver: it resolves previousCredential links over the LOCAL store (the
// substrate slice-17g filled in-process), so the audit assembly does no network fetch.
type localChainResolver struct{ svc *vcresolver.Service }

func (l localChainResolver) ResolveCredential(ctx context.Context, contentAddress string) (*vc.PipelinePassCredential, error) {
	return l.svc.ResolveVC(ctx, contentAddress)
}

// buildAuditRunner constructs the async audit runner, or returns (nil, nil) when the node
// has no consuming loop (no consumed heads register, so there is nothing to audit). The
// audit chainwalk's MaxDepth equals the batch resolver's max-depth (D-17h-4): neither
// component rejects a chain the other accepts.
func buildAuditRunner(
	queue *auditor.MemQueue,
	status *auditor.MemStatusStore,
	receipts *auditor.MemReceiptStore,
	vcSvc *vcresolver.Service,
	pool *memstore.Pool,
	didResolver resolver.Resolver,
	pipeCfg *pipelineconfig.Config,
) (*auditor.Runner, error) {
	if !hasConsumingLoop(pipeCfg) {
		return nil, nil
	}
	verifier := vc.NewVerifier(didResolver, ed25519.Verifier{})
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
