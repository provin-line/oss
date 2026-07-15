package main

import (
	"context"
	"fmt"

	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/pipeline/provenance"
	"github.com/provin-line/oss/pipeline/provenance/vcdid"
	"github.com/provin-line/oss/pipeline/sink"
	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/vc"
)

// sinkReceiptRegistrar is the composition-root sink.ReceiptIssuer: it signs a
// provin:sink-receipt over the consumed credential and commits it to the node's
// audit substrate in the load-bearing order the emissionRegistrar established —
// local store (so the audit runner, which resolves heads from the local
// vcresolver only, can dequeue it), a dedicated durable tlog, the audit queue —
// and only then, if configured, publishes it to a remote store.
//
// A sink receipt is never emitted in-band on the chain (the ChainTerminating
// invariant): local-before-remote ordering means a receipt is never externally
// visible without a local audit trail, and relying parties reach it via
// ResolveVC / ListAuditStatuses / bundle export. The signer is configured with
// TransformationClaim = provin:sink-receipt, so the credential it mints carries
// the identity claim (input == output, transforms nothing).
type sinkReceiptRegistrar struct {
	signer     provenance.ChainedSigner // TransformationClaim = provin:sink-receipt
	local      ingressStorer            // local StoreVC (returns the head content address)
	receiptLog tlog.Log                 // dedicated durable, hash-chained receipt log
	audit      auditRegistrar           // enqueues the receipt head for self-audit
	publisher  credentialPublisher      // optional remote VC-store publish (nil => skip)
}

var _ sink.ReceiptIssuer = (*sinkReceiptRegistrar)(nil)

// buildSinkReceiptRegistrar assembles the receipt issuer for a receipt-configured
// sink loop: a signer minting provin:sink-receipt under the loop's receipt issuer
// identity, plus the local store, a dedicated durable receipt log, the audit
// queue, and an optional remote publisher. It fails closed if the audit substrate
// (local store + audit queue) is absent — a receipt-configured sink that cannot
// make its receipts audit-reachable must not boot. newLog builds the durable
// per-loop log (the composition root's emission-log constructor, reused).
func buildSinkReceiptRegistrar(
	builder *vc.Builder,
	local ingressStorer,
	audit auditRegistrar,
	publisher credentialPublisher,
	newLog func(loopName, logID string, issuer pipelineconfig.IssuerConfig) (tlog.Log, error),
	lc pipelineconfig.LoopConfig,
) (sink.ReceiptIssuer, error) {
	if local == nil || audit == nil {
		return nil, fmt.Errorf("standalone: loop %q: sink receipts require a VC store and audit queue", lc.Name)
	}
	rc := lc.Sink.Receipt
	signer, err := vcdid.NewSigner(vcdid.Config{
		Builder:             builder,
		IssuerDID:           rc.Issuer.DID,
		KeyID:               rc.Issuer.KeyID,
		VerificationMethod:  rc.Issuer.VerificationMethod,
		PipelineID:          rc.PipelineID,
		ProcessID:           rc.ProcessID,
		TransformationClaim: vc.ClaimSinkReceipt,
	})
	if err != nil {
		return nil, fmt.Errorf("standalone: loop %q: sink receipt signer: %w", lc.Name, err)
	}
	// The receipt log is keyed by a stable, receipt-specific id (the receipt
	// issuer DID) — distinct from any producing loop's emission subject.
	receiptLog, err := newLog(lc.Name, "sink-receipt:"+rc.Issuer.DID, rc.Issuer)
	if err != nil {
		return nil, fmt.Errorf("standalone: loop %q: sink receipt log: %w", lc.Name, err)
	}
	return &sinkReceiptRegistrar{
		signer:     signer,
		local:      local,
		receiptLog: receiptLog,
		audit:      audit,
		publisher:  publisher,
	}, nil
}

// IssueReceipt signs the receipt (input == output == the consumed credential's
// outputHash — a receipt transforms nothing) and registers it local-first,
// remote-last. Each step is fail-closed and ordered; a failure before the remote
// publish leaves no externally-visible receipt without a local trail.
func (r *sinkReceiptRegistrar) IssueReceipt(ctx context.Context, consumed *vc.PipelinePassCredential) error {
	subject, err := consumed.Subject()
	if err != nil {
		return fmt.Errorf("sinkReceiptRegistrar: read consumed subject: %w", err)
	}
	if subject.OutputHash == "" {
		return fmt.Errorf("sinkReceiptRegistrar: consumed credential declares no outputHash")
	}
	// A receipt asserts identity over the consumed output: input == output.
	// payload is nil deliberately: the receipt attests an already-signed
	// credential's OutputHash and the registrar holds no output bytes to
	// re-hash, so the signer's defensive payload check is skipped (opt-out).
	receipt, err := r.signer.SignChainPreserving(ctx, nil, subject.OutputHash, subject.OutputHash, consumed)
	if err != nil {
		return fmt.Errorf("sinkReceiptRegistrar: sign receipt: %w", err)
	}
	b, err := receipt.MarshalJSON()
	if err != nil {
		return fmt.Errorf("sinkReceiptRegistrar: marshal receipt: %w", err)
	}

	// 1. Local store — the head must be locally resolvable before the audit runner
	// dequeues it. StoreVC returns the server-recomputed addresses; the queue is
	// body-keyed (see emissionregistrar.go on why the variant is not carried yet).
	res, err := r.local.StoreVC(ctx, b, "", 0)
	if err != nil {
		return fmt.Errorf("sinkReceiptRegistrar: local store receipt: %w", err)
	}
	// 2. Durable, hash-chained receipt log. Uses the raw tlog append, bypassing the
	// transport Emitter (whose tail recovery assumes emission sequence numbers).
	if _, err := r.receiptLog.Append(ctx, b); err != nil {
		return fmt.Errorf("sinkReceiptRegistrar: append receipt tlog: %w", err)
	}
	// 3. Enqueue the receipt head for self-audit (verifies receipt→consumed→…).
	if err := r.audit.Add(res.BodyAddress); err != nil {
		return fmt.Errorf("sinkReceiptRegistrar: enqueue receipt head: %w", err)
	}
	// 4. Optional remote publish — external visibility strictly after (1)–(3).
	if r.publisher != nil {
		if err := publishIssuedCredential(ctx, r.publisher, receipt, ""); err != nil {
			return err
		}
	}
	return nil
}
