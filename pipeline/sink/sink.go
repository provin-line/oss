// Package sink implements the Sink Process runtime: it consumes a
// pipeline-conformant envelope, verifies the credential (or chain), writes the
// payload to an external system, and produces nothing in-network. It is the
// runtime embodiment of contract.ChainTerminating.
//
// # Relationship to the Chained runtime
//
// The sink reuses the Chained runtime's ingress half — decode, strategy-driven
// verification, the payload↔credential binding gate, and the synchronous
// ingress-VC store — but has no transform/sign half. In its place is a single
// external write (Writer). The terminal Result carries a nil VC and nil
// Payload: a sink appends nothing to the chain (contract.Result).
//
// # SinkKind verdict policy
//
// Whether an invalid verdict is written or rejected is the deployed sink's
// SinkKind (contract.SinkKind), not a property of the sink type:
//
//   - observation-only: writes regardless of verdict — inspection tooling MAY
//     surface failed/indeterminate credentials. This is the home of
//     observation leniency, which producing processes never have.
//   - production / archival: fail-closed — only ConfidenceVerified is written;
//     any other verdict is StatusErrored (MUST reject).
//
// Leniency covers the VERIFICATION VERDICT (signature / DID / schema axes)
// only. The payload↔credential binding (sha256(payload) ==
// credentialSubject.outputHash) is a structural-correspondence gate enforced
// UNCONDITIONALLY for every kind: a sink must never emit a record pairing a
// credential with bytes it does not describe, even when surfacing an invalid
// verdict.
//
// # Store-on-verified
//
// The ingress VC is stored only when the verdict is ConfidenceVerified — the
// contract's IngressVCStore persists *verified* ingress VCs. An observation
// sink that writes an invalid-verdict credential does not store it.
//
// # production / archival obligations
//
// A production/archival sink enforces, beyond the verdict policy and binding
// gate: the local issuer allow-list (AllowIssuers — a consumed credential whose
// issuer DID matches no pattern is rejected before any store or write); receipt
// issuance (the ReceiptIssuer seam, called after the external write — MAY for
// production, MUST for archival); and, for archival, a durable reject log (the
// RejectLog seam — every reject records a RejectRecord). The signing, storage,
// audit-queue registration, and durable logging behind those seams live in the
// composition root, not this runtime.
//
// Still deferred: by-reference (nil) payload ingress is not implemented — it
// lands with the resolver client.
//
// # Result error split (mirrors chained)
//
// Domain failures (decode, store, binding, write, rejected verdict) are
// StatusErrored Results with a non-empty Error string and a nil Go error.
// Context cancellation returns a Go error.
package sink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/provin-line/oss/agentaccess"
	"github.com/provin-line/oss/allowlist"
	"github.com/provin-line/oss/appraisal"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/provenance"
	"github.com/provin-line/oss/vc"
)

// Record is the unit handed to a Writer: the consumed credential, the
// payload bytes it describes, and the verification verdict to surface
// alongside them.
type Record struct {
	Credential *vc.PipelinePassCredential
	Payload    []byte
	Verdict    *vc.VerifyResult
	// EvidenceView is non-nil for an evidence-qualified Agent delivery. It
	// names the exact selected spine and resolver snapshots evaluated locally.
	EvidenceView *appraisal.View
	// Delivery binds the actual payload bytes, head output hash, and local
	// accepted view. Legacy adjacent-only sinks leave it nil.
	Delivery *agentaccess.DeliveryRecord
}

// Writer delivers one consumed event to the external world. Implementations
// (console, warehouse, EDC, …) live in subpackages or extension repositories.
type Writer interface {
	Write(ctx context.Context, rec Record) error
}

// Appraiser performs synchronous full-chain appraisal and returns both the
// portable evidence view and the implementation's detailed verifier result.
// It is injected by the composition root; sink owns only call ordering.
type Appraiser interface {
	Appraise(ctx context.Context, head *vc.PipelinePassCredential) (*appraisal.View, *vc.VerifyResult, error)
}

// RejectReason classifies why an archival sink refused a consumed event. It is a
// closed set covering every reject stage — recording only some (e.g. verdict) would
// let an archival sink boot while under-delivering its "reject with audit log"
// obligation. A post-acceptance failure (external write, receipt) is NOT a reject
// and carries no reason: it is StatusErrored + slog, never a reject-log record.
type RejectReason string

const (
	// RejectDecodeFailure — the input envelope did not decode.
	RejectDecodeFailure RejectReason = "decode-failure"
	// RejectMalformedCredential — the credential's subject is unreadable or
	// declares no outputHash (binding undecidable).
	RejectMalformedCredential RejectReason = "malformed-credential"
	// RejectVerdict — a non-verified verdict at a fail-closed sink.
	RejectVerdict RejectReason = "verdict"
	// RejectAllowList — the consumed credential's issuer is not allow-listed.
	RejectAllowList RejectReason = "allow-list"
	// RejectBindingGate — the payload does not match the credential's outputHash.
	RejectBindingGate RejectReason = "binding-gate"
	// RejectByReferenceUnsupported — by-reference (nil payload) ingress, unimplemented.
	//
	// Deprecated: by-reference ingress is now implemented (RejectPayloadFetch /
	// RejectPayloadDeliveryViolation cover its failure modes). This value is no
	// longer emitted but is retained because it may appear as a historical value
	// in existing reject logs and archives; removing the identifier would break
	// consumers of that durable record.
	RejectByReferenceUnsupported RejectReason = "by-reference-unsupported"
	// RejectPayloadFetch — a by-reference payload could not be dereferenced from
	// the publisher's serving boundary (transient failure or a definitive miss).
	// A liveness failure, never a confidence verdict.
	RejectPayloadFetch RejectReason = "payload-fetch"
	// RejectPayloadDeliveryViolation — the envelope's payload presence contradicts
	// the agreed delivery mode (inline agreed but no payload, or by-reference
	// agreed but an inline payload arrived). A decidable protocol violation.
	RejectPayloadDeliveryViolation RejectReason = "payload-delivery-violation"
	// RejectIngressStoreFailure — the verified ingress VC could not be stored.
	RejectIngressStoreFailure RejectReason = "ingress-store-failure"
	// RejectAppraisal — exact-view construction, identity validation, or local
	// policy did not produce ACCEPT.
	RejectAppraisal RejectReason = "appraisal"
)

// RejectRecord is one durable reject-log entry. Identity fields are best-effort —
// empty when unknown at the reject point (e.g. a decode failure yields no
// credential hash or issuer). The record NEVER carries the payload: a sink must
// not hoard the bytes it refused in its evidence store.
type RejectRecord struct {
	// Timestamp is when the reject occurred.
	Timestamp time.Time `json:"timestamp"`
	// Reason is the closed-set reject class.
	Reason RejectReason `json:"reason"`
	// Detail is the human-readable reject message (no payload bytes).
	Detail string `json:"detail"`
	// CredentialHash is the consumed credential's content address, if it decoded.
	CredentialHash string `json:"credentialHash,omitempty"`
	// IssuerDID is the consumed credential's issuer, if readable.
	IssuerDID string `json:"issuerDid,omitempty"`
}

// RejectLog durably records an archival sink's rejects (hash-chained, durable).
// Configured only for the archival kind; nil disables reject recording.
type RejectLog interface {
	RecordReject(ctx context.Context, rec RejectRecord) error
}

// ReceiptIssuer signs and registers a sink receipt for one consumed credential.
// It is the sink runtime's seam to the network signing + registration layer:
// the sink itself neither signs nor stores. A receipt attests consumption (it is
// chain-preserving-signed over the consumed credential, transforms nothing) and
// is published to the local audit substrate — VC store + a dedicated tlog + the
// audit queue — and optionally to a remote store, but NEVER in-band on the chain
// (the ChainTerminating invariant). Implementations live in the composition root.
type ReceiptIssuer interface {
	IssueReceipt(ctx context.Context, consumed *vc.PipelinePassCredential) error
}

// Typed construction errors.
var (
	ErrInvalidStrategy = errors.New("sink: Strategy must be VerificationAdjacent — a sink verifies the immediately preceding credential it consumes")
	ErrInvalidKind     = errors.New("sink: Kind must be a known SinkKind (observation-only / production / archival)")
	ErrMissingCodec    = errors.New("sink: Codec is required")
	ErrMissingStore    = errors.New("sink: Store is required — verifying without storing breaks chain audits")
	ErrMissingWriter   = errors.New("sink: Writer is required")
	ErrMissingUpstream = errors.New("sink: UpstreamEndpoint is required")
	ErrMissingVerifier = errors.New("sink: Verifier is required")
	// ErrMissingPayloadResolver — a by-reference ingress needs a PayloadResolver
	// to dereference its nil payloads (fail closed at construction, never on the
	// first by-reference event).
	ErrMissingPayloadResolver = errors.New("sink: PayloadResolver is required when PayloadDelivery is by-reference")
	ErrInvalidAgentAppraisal  = errors.New("sink: Appraiser and a versioned AgentBoundaryID are required together and only on production or archival sinks")
)

// Config holds construction-time configuration for a Sink Process runtime.
type Config struct {
	// Strategy must be VerificationAdjacent (the only ingress verification a sink runs;
	// full-chain audit is the async audit runner's job, slice-17h).
	Strategy contract.VerificationStrategy
	// Kind is the deployed sink's handling discipline. Must be non-Unknown.
	Kind contract.SinkKind
	// Codec decodes the wire-form input envelope. Required.
	Codec contract.EnvelopeCodec
	// Verifier verifies the single immediately-preceding credential. Required.
	Verifier provenance.Verifier
	// Appraiser enables purpose-first evidence-qualified Agent access. When set,
	// it replaces adjacent-only verification as the delivery verdict source and
	// must produce a locally accepted exact EvidenceView before any writer call.
	// Nil retains the legacy adjacent-verification behavior.
	Appraiser Appraiser
	// AgentBoundaryID is the versioned identity written into successful delivery
	// records. Required exactly when Appraiser is set.
	AgentBoundaryID string
	// Store persists the verified ingress VC. Required.
	Store contract.IngressVCStore
	// Writer delivers the consumed event externally. Required.
	Writer Writer
	// Receipts, when non-nil, issues a sink receipt for each consumed event after
	// the external write. Required for archival (MUST emit receipts), optional for
	// production (MAY), nil for observation-only. The sink calls it; the signing,
	// local store, tlog append, audit-queue registration, and optional remote
	// publish are all its concern (see ReceiptIssuer).
	Receipts ReceiptIssuer
	// RejectLog, when non-nil, durably records every reject (archival's
	// reject-with-audit-log obligation). A reject-log write failure does not
	// change the reject outcome (the event is already refused); it is logged.
	RejectLog RejectLog
	// UpstreamEndpoint names where the ingress VC can later be fetched. Required.
	UpstreamEndpoint string
	// AllowIssuers is the sink's local issuer allow-list: a consumed credential is
	// admitted only if its issuer DID matches one of these patterns (segment-aware
	// globs, allowlist.Match; default-distrust). Empty means unrestricted — the
	// observation-only default. production/archival require a non-empty list at
	// boot (loadSinkConfig), so a misconfigured deployment fails closed rather
	// than silently accepting every issuer. This is the consumer-side half of the
	// "mutual" allow-list; the publisher side is the chainmanager subscription
	// allow-list — each is its own local config (see the sink README).
	AllowIssuers []string
	// PayloadDelivery is the agreed payload-delivery mode of this ingress. The
	// zero value (DeliveryInline) expects inline payload bytes; DeliveryByReference
	// dereferences a nil payload via PayloadResolver. A payload whose presence
	// contradicts the mode is a decidable protocol violation.
	PayloadDelivery contract.PayloadDelivery
	// PayloadResolver dereferences a by-reference payload by content address.
	// Required iff PayloadDelivery is DeliveryByReference (New fails closed
	// otherwise); unused for inline delivery.
	PayloadResolver contract.PayloadResolver
	// Observers are notified after every outcome (passed/errored).
	Observers []contract.ProcessObserver
	// Logger receives diagnostic output. nil = slog.Default().
	Logger *slog.Logger
	// Now is the clock used for ProcessEvent.Timestamp. nil = time.Now.
	Now func() time.Time
}

// Processor is the Sink Process runtime. Construct with New.
// *Processor implements contract.EventProcessor.
type Processor struct {
	cfg    Config
	logger *slog.Logger
	now    func() time.Time
}

// New validates cfg and returns a ready Processor.
func New(cfg Config) (*Processor, error) {
	if cfg.Strategy != contract.VerificationAdjacent {
		return nil, ErrInvalidStrategy
	}
	switch cfg.Kind {
	case contract.SinkObservationOnly, contract.SinkProduction, contract.SinkArchival:
		// valid
	default:
		return nil, ErrInvalidKind
	}
	if cfg.Codec == nil {
		return nil, ErrMissingCodec
	}
	if cfg.Store == nil {
		return nil, ErrMissingStore
	}
	if cfg.Writer == nil {
		return nil, ErrMissingWriter
	}
	if cfg.UpstreamEndpoint == "" {
		return nil, ErrMissingUpstream
	}
	if cfg.Verifier == nil {
		if cfg.Appraiser == nil {
			return nil, ErrMissingVerifier
		}
	}
	if cfg.Appraiser != nil {
		if cfg.Kind == contract.SinkObservationOnly || agentaccess.ValidateBoundaryID(cfg.AgentBoundaryID) != nil {
			return nil, ErrInvalidAgentAppraisal
		}
	} else if cfg.AgentBoundaryID != "" {
		return nil, ErrInvalidAgentAppraisal
	}
	if cfg.PayloadDelivery == contract.DeliveryByReference && cfg.PayloadResolver == nil {
		return nil, ErrMissingPayloadResolver
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Processor{cfg: cfg, logger: logger, now: now}, nil
}

// Process implements contract.EventProcessor for one consumed event.
func (p *Processor) Process(ctx context.Context, input []byte) (*contract.Result, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Stage 1 — Decode.
	envelope, err := p.cfg.Codec.UnmarshalEnvelope(input)
	if err != nil {
		return p.reject(ctx, RejectDecodeFailure, fmt.Sprintf("decode envelope: %v", err), nil, "", "", ""), nil
	}
	cred := envelope.Credential

	// consumedRef is the audit handle to the consumed credential (the head of
	// the chain this sink terminates). Best-effort: a Hash failure on an
	// already-decoded credential is degraded observability, not a reason to fail
	// the write — leave it empty in that case.
	consumedRef := ""
	if cred != nil {
		if h, herr := cred.Hash(); herr == nil {
			consumedRef = h
		}
	}

	// Stage 2 — Choose exactly one verification path. A purpose-first sink runs
	// synchronous full-chain appraisal and validates the exact view identity and
	// local decision. A legacy sink retains adjacent verification. The two are
	// not combined: combining independently-selected inputs would make it
	// unclear which evidence the delivery decision actually consumed.
	var evidenceView *appraisal.View
	var verifyResult *vc.VerifyResult
	if p.cfg.Appraiser != nil {
		evidenceView, verifyResult, err = p.cfg.Appraiser.Appraise(ctx, cred)
		if err != nil {
			if isCtxErr(err) {
				return nil, err
			}
			return p.reject(ctx, RejectAppraisal, fmt.Sprintf("exact-view appraisal failed: %v", err), nil, consumedRef, "", issuerDIDOf(cred)), nil
		}
		if evidenceView == nil || verifyResult == nil {
			return p.reject(ctx, RejectAppraisal, "exact-view appraiser returned no view or verifier result", nil, consumedRef, "", issuerDIDOf(cred)), nil
		}
		if err := evidenceView.ValidateID(); err != nil {
			return p.reject(ctx, RejectAppraisal, fmt.Sprintf("evidence view identity invalid: %v", err), nil, consumedRef, "", issuerDIDOf(cred)), nil
		}
		if evidenceView.PolicyDecision == nil || evidenceView.PolicyDecision.Decision != appraisal.DecisionAccept {
			decision := "missing"
			if evidenceView.PolicyDecision != nil {
				decision = string(evidenceView.PolicyDecision.Decision)
			}
			return p.reject(ctx, RejectAppraisal, fmt.Sprintf("local appraisal decision %s: production delivery requires ACCEPT", decision), &verifyResult.Overall, consumedRef, "", issuerDIDOf(cred)), nil
		}
	} else {
		verifyResult, err = p.cfg.Verifier.Verify(ctx, cred)
		if err != nil {
			if isCtxErr(err) {
				return nil, err
			}
			// A verification transport error (resolver outage, chain hole) IS the
			// indeterminate verdict — the verdict could not be computed. Synthesize
			// it and fall through to the SinkKind policy.
			p.logger.Warn("sink: verification error treated as indeterminate", "err", err)
			verifyResult = &vc.VerifyResult{Overall: vc.ConfidenceIndeterminate}
		}
	}
	verdict := verifyResult.Overall

	// Stage 3 — SinkKind verdict policy. Observation writes regardless;
	// production/archival reject any non-verified verdict.
	if p.cfg.Kind != contract.SinkObservationOnly && verdict != vc.ConfidenceVerified {
		return p.reject(ctx, RejectVerdict, fmt.Sprintf("verification verdict %v: a %v sink rejects non-verified credentials (fail-closed)", verdict, kindName(p.cfg.Kind)), &verdict, consumedRef, "", issuerDIDOf(cred)), nil
	}

	// Stage 3.5 — Issuer allow-list. When configured (production/archival admit
	// only allow-listed issuers), reject a credential whose issuer DID matches no
	// pattern BEFORE any store or write. An empty list is unrestricted
	// (observation-only). A nil credential yields an empty issuer, which never
	// matches — fail-closed.
	if len(p.cfg.AllowIssuers) > 0 {
		issuer := ""
		if cred != nil {
			issuer = cred.Issuer()
		}
		if !p.issuerAllowed(issuer) {
			return p.reject(ctx, RejectAllowList, fmt.Sprintf("issuer %q is not in the sink allow-list (fail-closed)", issuer), &verdict, consumedRef, "", issuer), nil
		}
	}

	// Stage 4 — Store the ingress VC (only when verified — the store persists
	// verified ingress VCs). Synchronous; failure is a loud drop. This runs
	// BEFORE the binding gate (Stage 6): a verified credential whose payload is
	// later found tampered is still stored — the credential is genuine; only its
	// transport was tampered. (Store-before-binding parity with chained.)
	if verdict == vc.ConfidenceVerified {
		if err := p.cfg.Store.StoreIngressVC(ctx, cred, p.cfg.UpstreamEndpoint); err != nil {
			if isCtxErr(err) {
				return nil, err
			}
			return p.reject(ctx, RejectIngressStoreFailure, fmt.Sprintf("store ingress VC: %v — never continue without the audit trail", err), &verdict, consumedRef, "", issuerDIDOf(cred)), nil
		}
	}

	// Stage 5 — Subject. Read BEFORE payload acquisition: a by-reference fetch
	// keys on the declared outputHash, and the binding gate compares against it.
	subject, err := cred.Subject()
	if err != nil {
		return p.reject(ctx, RejectMalformedCredential, fmt.Sprintf("credential subject unreadable: %v", err), &verdict, consumedRef, "", issuerDIDOf(cred)), nil
	}
	if subject.OutputHash == "" {
		return p.reject(ctx, RejectMalformedCredential, "credential declares no outputHash: binding undecidable, fail closed", &verdict, consumedRef, "", issuerDIDOf(cred)), nil
	}

	// Stage 5.5 — Payload acquisition per agreed delivery mode. A payload whose
	// presence contradicts the mode is a decidable protocol violation; a
	// by-reference nil is dereferenced from the serving boundary by outputHash.
	// Fetch runs only here (after verify + verdict + allow-list + store), so the
	// sink never fetches bytes for a credential it will refuse.
	payload, rej, ctxErr := p.acquirePayload(ctx, envelope, subject.OutputHash, verdict, consumedRef, cred)
	if ctxErr != nil {
		return nil, ctxErr
	}
	if rej != nil {
		return rej, nil
	}
	// inputHash is the hash of the bytes flowing into the sink — its observer
	// "input" (and, once binding passes, == the consumed credential's outputHash).
	inputHash := hashBytes(payload)

	// Stage 6 — Payload↔credential binding. Unconditional for every SinkKind:
	// a sink must never emit a record pairing a credential with bytes it does
	// not describe. Observation leniency covers the verdict, not this gate. For a
	// by-reference payload this is the sole integrity check on the fetched bytes —
	// the serving boundary is untrusted.
	if inputHash != subject.OutputHash {
		return p.reject(ctx, RejectBindingGate, fmt.Sprintf("payload does not match the credential's outputHash (payload %s, credential declares %s): tampered or substituted bytes", inputHash, subject.OutputHash), &verdict, consumedRef, inputHash, issuerDIDOf(cred)), nil
	}

	// Stage 7 — Construct the exact successful-delivery record, then perform the
	// only external writer call. Construction is before the call so the writer
	// cannot receive bytes without their binding; the record becomes a delivered
	// artifact only if Write succeeds.
	var delivery *agentaccess.DeliveryRecord
	if evidenceView != nil {
		delivery, err = agentaccess.NewDelivery(p.cfg.AgentBoundaryID, payload, subject.OutputHash, evidenceView)
		if err != nil {
			return p.reject(ctx, RejectAppraisal, fmt.Sprintf("construct Agent delivery: %v", err), &verdict, consumedRef, inputHash, issuerDIDOf(cred)), nil
		}
	}
	if err := p.cfg.Writer.Write(ctx, Record{Credential: cred, Payload: payload, Verdict: verifyResult, EvidenceView: evidenceView, Delivery: delivery}); err != nil {
		if isCtxErr(err) {
			return nil, err
		}
		return p.errored(ctx, fmt.Sprintf("external write: %v", err), &verdict, consumedRef, inputHash), nil
	}

	// Stage 7.5 — Receipt issuance. After the external write, a receipt-configured
	// sink signs a provin:sink-receipt over the consumed credential and registers
	// it (local store → tlog → audit queue → optional remote — the issuer's
	// concern). The write is at-most-once and is NOT rolled back on a receipt
	// failure: the receipt path only ADDS an audit trail, and its local-before-
	// remote ordering means a "remote-visible but no local trail" state cannot
	// occur. A receipt failure is StatusErrored — the "write-done, receipt-absent"
	// residual is detectable via audit not_found + tlog diff (spec D-1).
	if p.cfg.Receipts != nil {
		if err := p.cfg.Receipts.IssueReceipt(ctx, cred); err != nil {
			if isCtxErr(err) {
				return nil, err
			}
			return p.errored(ctx, fmt.Sprintf("issue sink receipt: %v (external write already completed — at-most-once, not rolled back)", err), &verdict, consumedRef, inputHash), nil
		}
	}

	// Stage 8 — Terminal Result: a sink produces nothing in-network.
	r := &contract.Result{
		Status:     contract.StatusPassed,
		Confidence: &verdict,
	}
	p.notify(ctx, r, consumedRef, inputHash)
	return r, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func isCtxErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// acquirePayload resolves the event's payload bytes per the agreed delivery
// mode. It returns either the bytes (rej and ctxErr both nil), a reject Result
// (rej non-nil), or a context error (ctxErr non-nil). The fail-closed table:
//
//	inline       + present → the inline bytes
//	inline       + nil     → RejectPayloadDeliveryViolation (payload stripped in error)
//	by-reference + nil     → fetch(UpstreamEndpoint, outputHash) via PayloadResolver
//	by-reference + present → RejectPayloadDeliveryViolation (leak / export misconfig)
//
// A fetch failure (transient or a definitive miss) is RejectPayloadFetch — a
// liveness failure, never a confidence verdict. Context cancellation is returned
// as ctxErr for the caller to propagate as a Go error (like every other stage),
// NOT recorded as a reject — a shutdown-interrupted fetch must not pollute an
// archival sink's durable reject log. Cancellation is detected via ctx.Err()
// rather than the fetch error's type, because the network resolver returns a
// transport-wrapped error that may not unwrap to context.Canceled.
func (p *Processor) acquirePayload(ctx context.Context, envelope *contract.Envelope, outputHash string, verdict vc.ConfidenceState, consumedRef string, cred *vc.PipelinePassCredential) (payload []byte, rej *contract.Result, ctxErr error) {
	switch p.cfg.PayloadDelivery {
	case contract.DeliveryByReference:
		if envelope.Payload != nil {
			return nil, p.reject(ctx, RejectPayloadDeliveryViolation, "by-reference delivery agreed but the envelope carries an inline payload (export-seam misconfiguration; possible payload leak)", &verdict, consumedRef, "", issuerDIDOf(cred)), nil
		}
		bytes, err := p.cfg.PayloadResolver.ResolvePayload(ctx, p.cfg.UpstreamEndpoint, outputHash)
		if err != nil {
			if cErr := ctx.Err(); cErr != nil {
				return nil, nil, cErr
			}
			return nil, p.reject(ctx, RejectPayloadFetch, fmt.Sprintf("fetch by-reference payload at %s from %s: %v", outputHash, p.cfg.UpstreamEndpoint, err), &verdict, consumedRef, "", issuerDIDOf(cred)), nil
		}
		return bytes, nil, nil
	default: // DeliveryInline
		if envelope.Payload == nil {
			return nil, p.reject(ctx, RejectPayloadDeliveryViolation, "inline delivery agreed but the envelope carries no payload (stripped in error)", &verdict, consumedRef, "", issuerDIDOf(cred)), nil
		}
		return envelope.Payload, nil, nil
	}
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// issuerAllowed reports whether issuer matches any configured allow-issuers
// pattern. A malformed pattern (which loadSinkConfig rejects at boot) is treated
// as non-matching here — fail-closed, never trust an unvalidatable rule.
func (p *Processor) issuerAllowed(issuer string) bool {
	for _, pat := range p.cfg.AllowIssuers {
		if ok, err := allowlist.Match(pat, issuer); err == nil && ok {
			return true
		}
	}
	return false
}

func kindName(k contract.SinkKind) string {
	switch k {
	case contract.SinkObservationOnly:
		return "observation-only"
	case contract.SinkProduction:
		return "production"
	case contract.SinkArchival:
		return "archival"
	default:
		return "unknown"
	}
}

// reject records a credential-rejection outcome to the reject log (when
// configured — archival's obligation) and returns the StatusErrored Result. Only
// the closed set of reject stages calls this; a post-acceptance failure (external
// write, receipt) uses errored, which records nothing. A reject-log write failure
// does not change the reject outcome — the event is already refused — but is
// logged loudly so a broken archival audit trail is visible.
func (p *Processor) reject(ctx context.Context, reason RejectReason, msg string, confidence *vc.ConfidenceState, consumedVCRef, inputHash, issuerDID string) *contract.Result {
	if p.cfg.RejectLog != nil {
		rec := RejectRecord{
			Timestamp:      p.now(),
			Reason:         reason,
			Detail:         msg,
			CredentialHash: consumedVCRef,
			IssuerDID:      issuerDID,
		}
		if err := p.cfg.RejectLog.RecordReject(ctx, rec); err != nil {
			p.logger.Error("sink: reject-log write failed", "reason", reason, "err", err)
		}
	}
	return p.errored(ctx, msg, confidence, consumedVCRef, inputHash)
}

// issuerDIDOf returns cred's issuer DID, or "" when cred is nil (best-effort
// identity for a reject record).
func issuerDIDOf(cred *vc.PipelinePassCredential) string {
	if cred == nil {
		return ""
	}
	return cred.Issuer()
}

func (p *Processor) errored(ctx context.Context, msg string, confidence *vc.ConfidenceState, consumedVCRef, inputHash string) *contract.Result {
	r := &contract.Result{
		Status:     contract.StatusErrored,
		Error:      msg,
		Confidence: confidence,
	}
	p.notify(ctx, r, consumedVCRef, inputHash)
	return r
}

// notify delivers a ProcessEvent to every observer. A sink issues nothing and
// produces nothing in-network, so IssuedVCRef and OutputHash stay empty; the
// audit identity rides ConsumedVCRef (the terminated head credential) and
// InputHash (the consumed payload). consumedVCRef/inputHash may be empty on
// early-failure paths where they are not yet known.
func (p *Processor) notify(ctx context.Context, r *contract.Result, consumedVCRef, inputHash string) {
	if len(p.cfg.Observers) == 0 {
		return
	}
	ev := contract.ProcessEvent{
		Result:        r,
		InputHash:     inputHash,
		ConsumedVCRef: consumedVCRef,
		// IssuedVCRef and OutputHash stay empty: a sink issues and produces nothing.
		Timestamp: p.now(),
	}
	for _, obs := range p.cfg.Observers {
		if err := obs.OnProcessComplete(ctx, ev); err != nil {
			p.logger.Error("observer error", "err", err)
		}
	}
}
