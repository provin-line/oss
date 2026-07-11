// Package aggregate implements the aggregate Source Process runtime: a stateful
// pool + window mechanic that consumes N Pipeline-conformant ingress inputs and,
// on a timer/window trigger, folds them into a single FirstDrop carrying a
// multi-source vc.SourceCommitment (transformationClaim provin:aggregate).
//
// It is the stateful counterpart of the N=0 ingest runtime: where ingest signs
// one external input per inbound event, the aggregate pools verified inputs and
// emits on its OWN trigger. It therefore implements contract.Process directly
// (it owns its Run loop and timer) rather than contract.EventProcessor — timer/
// window mechanics never pass through the one-input→one-result driver.
//
// # Lifecycle (per consumed input, in each ingress handler)
//
//  1. decode the envelope (credential + payload);
//  2. adjacent-verify the ingress credential (fail-closed: only Verified pools);
//  3. enforce the payload↔credential binding (sha256(payload) == outputHash) —
//     a verified credential does not make its accompanying bytes trustworthy;
//  4. StoreIngressVC synchronously (fail-closed) — the IngressVCStore
//     implementation owns audit-head registration;
//  5. admit into the pool (content-address dedup).
//
// # Lifecycle (per window, on each tick)
//
//  1. drain the pooled inputs (empty window → skip, no emit);
//  2. Fold the inputs into the aggregate output payload (business logic seam);
//  3. strict-JSON-gate the fold output (never sign malformed JSON);
//  4. SignAggregateFirstDrop over the consumed credentials;
//  5. emit (publish + emission log) via the shared transport.Emitter;
//  6. notify observers.
//
// # Concurrency
//
// Ingress handlers run concurrently (one goroutine per subscription); the pool
// is guarded by a mutex. foldOnce snapshots-and-clears the pool under the lock,
// then folds/signs/emits outside it. foldOnce is also the deterministic test
// seam (mirroring auditor.Runner.drainOnce): Run calls it on each tick, tests
// call it directly.
package aggregate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/provenance"
	"github.com/provin-line/oss/pipeline/transport"
	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/vc"
)

// Typed sentinel errors for construction validation.
var (
	ErrNoIngress       = errors.New("aggregate: at least one Ingress is required")
	ErrMissingSigner   = errors.New("aggregate: Signer is required")
	ErrMissingVerifier = errors.New("aggregate: Verifier is required")
	ErrMissingStore    = errors.New("aggregate: Store is required")
	ErrMissingPub      = errors.New("aggregate: Publisher is required")
	ErrMissingCodec    = errors.New("aggregate: Codec is required")
	ErrMissingEmission = errors.New("aggregate: Emission is required")
	ErrMissingFold     = errors.New("aggregate: Fold is required")
	// ErrMissingPayloadResolver — a by-reference ingress needs a PayloadResolver.
	ErrMissingPayloadResolver = errors.New("aggregate: PayloadResolver is required when an ingress is by-reference")
	ErrBadWindow              = errors.New("aggregate: Window must be > 0")
)

// PooledInput is one verified, audit-stored ingress item awaiting a fold.
type PooledInput struct {
	// Credential is the verified ingress credential — a source for the window's
	// SourceCommitment.
	Credential *vc.PipelinePassCredential
	// Payload is the ingress data bytes, bound to Credential.OutputHash.
	Payload []byte
}

// Fold maps a window's consumed inputs to the aggregate OUTPUT payload bytes —
// the aggregator's business logic. The source COMMITMENT is computed over the
// inputs' credentials by the signer; Fold produces the data the aggregate emits.
// The output must be canonical JSON (it is strict-gated before signing).
type Fold interface {
	Fold(ctx context.Context, inputs []PooledInput) ([]byte, error)
}

// aggregateFirstDropSigner is the narrow consumer-side signer capability the
// aggregate runtime exercises (only the aggregate FirstDrop path). Depending on
// this rather than the wider provenance.SourceSigner keeps SignFirstDrop off the
// aggregate's surface (interface segregation; slice-17k D-17k-3). *vcdid.Signer
// and the publishing decorator both satisfy it.
type aggregateFirstDropSigner interface {
	SignAggregateFirstDrop(ctx context.Context, payload []byte, outputHash string, sources []*vc.PipelinePassCredential) (*vc.PipelinePassCredential, error)
}

// EmissionRegistrar makes an emitted aggregate credential durable and auditable BEFORE it is
// broadcast (slice-17o D-17o-3/4): the composition-root impl persists the credential to the
// node's local store (so the audit runner can resolve the head), records the consumed-source
// content addresses as the audit receipt, enqueues the head, and (if a remote VC store is
// configured) publishes it there — all fail-closed and ordered, so the credential is never
// broadcast without a local audit trail. Optional: nil leaves the runtime broadcast-only
// (the pre-17o behavior). Consumer-defined here (pointing inward) — the concrete impl lives
// in the composition root, honoring the network/↔pipeline/ layer rule (D-17o-8).
type EmissionRegistrar interface {
	RegisterEmission(ctx context.Context, cred *vc.PipelinePassCredential, consumedHashes []string) error
}

// Ingress is one upstream subscription the aggregate pools from. UpstreamEndpoint
// names where each consumed credential can later be fetched (the StoreIngressVC
// hint). Subscribers are injected — mapping subjects→Subscriber is the dataplane
// wiring slice's concern, keeping this runtime broker-free.
type Ingress struct {
	Subscriber       transport.Subscriber
	UpstreamEndpoint string
	// PayloadDelivery is the agreed payload-delivery mode of THIS ingress. The
	// zero value (DeliveryInline) expects inline payload bytes; DeliveryByReference
	// dereferences a nil payload via PayloadResolver.
	PayloadDelivery contract.PayloadDelivery
	// PayloadResolver dereferences a by-reference payload by content address.
	// Required iff PayloadDelivery is DeliveryByReference (New fails closed).
	PayloadResolver contract.PayloadResolver
}

// Config constructs a Process.
type Config struct {
	Ingress   []Ingress
	Window    time.Duration
	Signer    aggregateFirstDropSigner
	Verifier  provenance.Verifier
	Store     contract.IngressVCStore
	Publisher transport.Publisher
	Codec     contract.EnvelopeCodec
	Emission  tlog.Log
	Fold      Fold
	// SelfAudit registers each emitted aggregate head for consumed-set self-audit before it
	// is broadcast (slice-17o). Optional: nil leaves the runtime broadcast-only.
	SelfAudit EmissionRegistrar
	// PayloadRetainer, when non-nil, durably retains each emitted aggregate head's
	// payload before publishing so a by-reference subscriber can dereference it
	// (the producer half of by-reference delivery). Optional; nil leaves the
	// aggregate an inline producer.
	PayloadRetainer transport.PayloadRetainer
	// StrippedPublisher, when non-nil, makes the aggregate's emitter dual-emit:
	// a stripped (Payload: nil) form of every emitted head additionally
	// publishes to it, under the same sequence number as the primary publish
	// (see transport.WithStrippedPublisher — the export seam's mechanism for
	// applying an agreed by-reference delivery mode). Optional; nil leaves the
	// aggregate single-publish, byte-for-byte the pre-dual-emit behavior.
	StrippedPublisher transport.Publisher
	// Observers are notified after each window emit (fire-and-forget). Optional.
	Observers []contract.ProcessObserver
	// Logger defaults to slog.Default(); Now defaults to time.Now.
	Logger *slog.Logger
	Now    func() time.Time
	// Tick optionally overrides the window timer for deterministic tests; nil
	// uses time.NewTicker(Window).
	Tick <-chan time.Time
	// PoolCap bounds the pool between ticks (drop-newest with a loud log on
	// overflow). 0 means unbounded (PoC default; bounding is wiring-tunable).
	PoolCap int
}

// Process is the aggregate Source Process runtime. It implements contract.Process.
type Process struct {
	cfg     Config
	logger  *slog.Logger
	now     func() time.Time
	emitter *transport.Emitter

	mu   sync.Mutex
	pool []PooledInput
	seen map[string]bool // content-address dedup within the current window
}

var _ contract.Process = (*Process)(nil)

// New validates cfg and returns a Process.
func New(cfg Config) (*Process, error) {
	switch {
	case len(cfg.Ingress) == 0:
		return nil, ErrNoIngress
	case cfg.Signer == nil:
		return nil, ErrMissingSigner
	case cfg.Verifier == nil:
		return nil, ErrMissingVerifier
	case cfg.Store == nil:
		return nil, ErrMissingStore
	case cfg.Publisher == nil:
		return nil, ErrMissingPub
	case cfg.Codec == nil:
		return nil, ErrMissingCodec
	case cfg.Emission == nil:
		return nil, ErrMissingEmission
	case cfg.Fold == nil:
		return nil, ErrMissingFold
	case cfg.Window <= 0 && cfg.Tick == nil:
		return nil, ErrBadWindow
	}
	for i, ing := range cfg.Ingress {
		if ing.Subscriber == nil {
			// Fail at construction, not with a nil deref in Run's subscription
			// loop — the wiring slice maps subjects→subscribers and a miss here
			// must be a config error, not a startup panic.
			return nil, fmt.Errorf("aggregate: Ingress[%d] has a nil Subscriber", i)
		}
		if ing.PayloadDelivery == contract.DeliveryByReference && ing.PayloadResolver == nil {
			return nil, fmt.Errorf("aggregate: Ingress[%d] is by-reference but has no PayloadResolver: %w", i, ErrMissingPayloadResolver)
		}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	// Construction-time seed read; New has no ctx (the process owns its
	// lifecycle from Run) — Background is deliberate here.
	var emitterOpts []transport.EmitterOption
	if cfg.PayloadRetainer != nil {
		emitterOpts = append(emitterOpts, transport.WithPayloadRetainer(cfg.PayloadRetainer))
	}
	if cfg.StrippedPublisher != nil {
		emitterOpts = append(emitterOpts, transport.WithStrippedPublisher(cfg.StrippedPublisher))
	}
	emitter, err := transport.NewEmitter(context.Background(), cfg.Publisher, cfg.Codec, cfg.Emission, logger, emitterOpts...)
	if err != nil {
		return nil, err
	}
	return &Process{
		cfg:     cfg,
		logger:  logger,
		now:     now,
		emitter: emitter,
		seen:    map[string]bool{},
	}, nil
}

// ChainBehavior is ChainFirstDrop: a timer/window trigger always yields a fresh
// chain origin (batch-of-1 included).
func (p *Process) ChainBehavior() contract.ChainBehavior { return contract.ChainFirstDrop }

// VerificationStrategy is VerificationAdjacent: each consumed Pipeline-conformant
// input is adjacent-verified before pooling.
func (p *Process) VerificationStrategy() contract.VerificationStrategy {
	return contract.VerificationAdjacent
}

// Run subscribes every ingress, then folds on each window tick until ctx is
// cancelled, at which point it drains the subscribers, applies the partial-window
// policy (discard), and closes the publisher.
func (p *Process) Run(ctx context.Context) error {
	var subscribed []Ingress
	for _, ing := range p.cfg.Ingress {
		ing := ing
		if err := ing.Subscriber.Subscribe(func(data []byte) {
			p.handleIngress(ctx, data, ing)
		}); err != nil {
			// Drain the already-registered subscriptions so no handler keeps
			// admitting under the caller's still-live context after a startup
			// failure.
			for _, s := range subscribed {
				if derr := s.Subscriber.Drain(); derr != nil {
					p.logger.Error("aggregate: drain after subscribe failure", "err", derr)
				}
			}
			return err
		}
		subscribed = append(subscribed, ing)
	}

	tick := p.cfg.Tick
	if tick == nil {
		t := time.NewTicker(p.cfg.Window)
		defer t.Stop()
		tick = t.C
	}

	for {
		select {
		case <-ctx.Done():
			return p.shutdown()
		case <-tick:
			p.foldOnce(ctx)
		}
	}
}

// handleIngress runs per inbound message in a subscription goroutine: decode →
// verify → bind → store → admit. Every failure drops the input (fail-closed):
// nothing un-verified, un-bound, or un-stored ever reaches the pool.
func (p *Process) handleIngress(ctx context.Context, data []byte, ing Ingress) {
	env, err := p.cfg.Codec.UnmarshalEnvelope(data)
	if err != nil {
		p.logger.Error("aggregate: decode ingress envelope", "err", err)
		return
	}
	if env.Credential == nil {
		p.logger.Error("aggregate: ingress envelope has no credential — dropping")
		return
	}
	cred := env.Credential

	// Adjacent verification — fail-closed: only a Verified credential pools.
	res, err := p.cfg.Verifier.Verify(ctx, cred)
	if err != nil {
		p.logger.Error("aggregate: verify ingress credential", "err", err)
		return
	}
	if res == nil || res.Overall != vc.ConfidenceVerified {
		p.logger.Warn("aggregate: ingress credential not Verified — dropping")
		return
	}

	// Subject — read before payload acquisition (a by-reference fetch keys on the
	// declared outputHash, and the binding gate compares against it).
	subj, err := cred.Subject()
	if err != nil {
		p.logger.Error("aggregate: ingress credential subject", "err", err)
		return
	}
	if subj.OutputHash == "" {
		p.logger.Warn("aggregate: ingress credential declares no outputHash — binding undecidable, dropping")
		return
	}

	// Payload acquisition per the ingress's agreed delivery mode (fail-closed);
	// dropped inputs never pool. A by-reference fetch runs only after verification.
	payload, ok := p.acquirePayload(ctx, env, subj.OutputHash, ing)
	if !ok {
		return
	}

	// Payload↔credential binding — a verified credential does not make its bytes
	// trustworthy, and a fetched by-reference payload is served by an untrusted
	// boundary. The binding gate is the sole integrity check.
	if hashPayload(payload) != subj.OutputHash {
		p.logger.Warn("aggregate: ingress payload does not bind to credential outputHash — dropping")
		return
	}

	// Store synchronously before pooling (fail-closed). The store implementation
	// owns audit-head registration.
	if err := p.cfg.Store.StoreIngressVC(ctx, cred, ing.UpstreamEndpoint); err != nil {
		p.logger.Error("aggregate: store ingress VC — dropping", "err", err)
		return
	}

	p.admit(PooledInput{Credential: cred, Payload: payload})
}

// acquirePayload resolves an ingress message's payload bytes per the ingress's
// agreed delivery mode, returning ok == false (after logging the drop) on any
// mode violation or fetch failure — this runtime drops fail-closed rather than
// producing a reject Result. The fail-closed table:
//
//	inline       + present → the inline bytes
//	inline       + nil     → drop (payload stripped in error)
//	by-reference + nil     → fetch(UpstreamEndpoint, outputHash) via PayloadResolver
//	by-reference + present → drop (leak / export misconfiguration)
//
// A fetch failure is a liveness drop, never a confidence question (a dropped
// input simply does not pool).
func (p *Process) acquirePayload(ctx context.Context, env *contract.Envelope, outputHash string, ing Ingress) ([]byte, bool) {
	switch ing.PayloadDelivery {
	case contract.DeliveryByReference:
		if env.Payload != nil {
			p.logger.Warn("aggregate: by-reference delivery agreed but inline payload present — dropping")
			return nil, false
		}
		bytes, err := ing.PayloadResolver.ResolvePayload(ctx, ing.UpstreamEndpoint, outputHash)
		if err != nil {
			p.logger.Warn("aggregate: fetch by-reference payload — dropping", "err", err)
			return nil, false
		}
		return bytes, true
	default: // DeliveryInline
		if env.Payload == nil {
			p.logger.Warn("aggregate: inline delivery agreed but no payload — dropping")
			return nil, false
		}
		return env.Payload, true
	}
}

// admit adds a verified+stored input to the pool, deduplicating by content
// address within the current window. Bounded by PoolCap (drop-newest, loud).
func (p *Process) admit(in PooledInput) {
	h, err := in.Credential.Hash()
	if err != nil {
		p.logger.Error("aggregate: hash ingress credential — dropping", "err", err)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen[h] {
		return // duplicate within this window — the signer would fail closed
	}
	if p.cfg.PoolCap > 0 && len(p.pool) >= p.cfg.PoolCap {
		p.logger.Warn("aggregate: pool at capacity — dropping newest input", "cap", p.cfg.PoolCap)
		return
	}
	p.seen[h] = true
	p.pool = append(p.pool, in)
}

// foldOnce performs exactly one window fold: snapshot+clear the pool under the
// lock, then fold → strict-gate → sign → emit → notify outside it. Returns
// whether it emitted. It is the deterministic test seam and Run's per-tick step.
// An empty window is skipped (no emit).
func (p *Process) foldOnce(ctx context.Context) bool {
	p.mu.Lock()
	inputs := p.pool
	p.pool = nil
	p.seen = map[string]bool{}
	p.mu.Unlock()

	if len(inputs) == 0 {
		return false // empty window: skip, do not emit
	}

	output, err := p.cfg.Fold.Fold(ctx, inputs)
	if err != nil {
		p.logger.Error("aggregate: fold", "err", err, "inputs", len(inputs))
		p.notifyErr(ctx)
		return false
	}
	// Strict canonical-JSON gate: never sign a malformed fold output.
	var strictOut interface{}
	if err := canon.NewStrictDecoder(output).Decode(&strictOut); err != nil {
		p.logger.Error("aggregate: fold output failed strict-JSON gate", "err", err)
		p.notifyErr(ctx)
		return false
	}

	outputHash := hashPayload(output)
	creds := make([]*vc.PipelinePassCredential, len(inputs))
	for i, in := range inputs {
		creds[i] = in.Credential
	}

	cred, err := p.cfg.Signer.SignAggregateFirstDrop(ctx, output, outputHash, creds)
	if err != nil {
		p.logger.Error("aggregate: sign aggregate FirstDrop", "err", err)
		p.notifyErr(ctx)
		return false
	}

	// Hash the issued credential BEFORE publishing (slice-17o): the head content address is
	// the observer ref AND the self-audit receipt/queue key, so a hash failure must abort the
	// emit (it is an internal invariant violation, and we never broadcast an un-referenceable
	// credential).
	ref, err := cred.Hash()
	if err != nil {
		p.logger.Error("aggregate: hash issued aggregate credential", "err", err)
		p.notifyErr(ctx)
		return false
	}

	// Register the emission for consumed-set self-audit BEFORE broadcasting (slice-17o
	// D-17o-3): local store + receipt + enqueue (+ optional remote publish), fail-closed. A
	// failure aborts the emit — the credential is never broadcast without a local audit trail
	// (the StoreIngressVC precedent). The consumed set is the pooled inputs' content
	// addresses, captured from the exact set that computed SourceRoot.
	if p.cfg.SelfAudit != nil {
		consumed := make([]string, 0, len(inputs))
		for _, in := range inputs {
			ch, err := in.Credential.Hash()
			if err != nil {
				p.logger.Error("aggregate: hash consumed source for receipt", "err", err)
				p.notifyErr(ctx)
				return false
			}
			consumed = append(consumed, ch)
		}
		if err := p.cfg.SelfAudit.RegisterEmission(ctx, cred, consumed); err != nil {
			p.logger.Error("aggregate: register emission for self-audit — dropping", "err", err)
			p.notifyErr(ctx)
			return false
		}
	}

	if err := p.emitter.Emit(ctx, cred, output); err != nil {
		p.logger.Error("aggregate: emit aggregate FirstDrop — dropping", "err", err)
		p.notifyErr(ctx)
		return false
	}

	// Every pooled input passed adjacent verification (VerificationAdjacent), so
	// the aggregate output carries a Verified confidence — matching chained/sink,
	// so observers don't read it as "no verification ran".
	verified := vc.ConfidenceVerified
	p.notify(ctx, &contract.Result{Status: contract.StatusPassed, VC: cred, Payload: output, Confidence: &verified}, outputHash, ref)
	return true
}

// shutdown drains every ingress subscriber, discards any partial window (default
// policy), and closes the outbound publisher. The shared broker connection is
// closed by the composition root, not here.
func (p *Process) shutdown() error {
	var firstErr error
	for _, ing := range p.cfg.Ingress {
		if err := ing.Subscriber.Drain(); err != nil {
			p.logger.Error("aggregate: drain subscriber", "err", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	// Partial-window policy: discard (PoC default — matches auditor/batchresolver
	// returning on ctx.Done without a final flush).
	if err := p.cfg.Publisher.Close(); err != nil {
		p.logger.Error("aggregate: publisher close", "err", err)
		if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// notify delivers a passed ProcessEvent (InputHash empty — an aggregate has no
// single input; OutputHash + IssuedVCRef set) to every observer, fire-and-forget.
func (p *Process) notify(ctx context.Context, r *contract.Result, outputHash, issuedRef string) {
	for _, obs := range p.cfg.Observers {
		ev := contract.ProcessEvent{
			Result:      r,
			OutputHash:  outputHash,
			IssuedVCRef: issuedRef,
			Timestamp:   p.now(),
		}
		if err := obs.OnProcessComplete(ctx, ev); err != nil {
			p.logger.Error("aggregate: observer error", "err", err)
		}
	}
}

// notifyErr delivers an errored ProcessEvent (no credential emitted) to observers.
func (p *Process) notifyErr(ctx context.Context) {
	for _, obs := range p.cfg.Observers {
		ev := contract.ProcessEvent{
			Result:    &contract.Result{Status: contract.StatusErrored},
			Timestamp: p.now(),
		}
		if err := obs.OnProcessComplete(ctx, ev); err != nil {
			p.logger.Error("aggregate: observer error", "err", err)
		}
	}
}

// hashPayload returns the "sha256:<hex>" content address of payload — the runtime
// hash format used across the pipeline (matches ingest/chained).
func hashPayload(payload []byte) string {
	sum := sha256.Sum256(payload)
	return fmt.Sprintf("sha256:%s", hex.EncodeToString(sum[:]))
}
