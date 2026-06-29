package auditor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/provin-line/oss/vc"
)

// HoleError is the capability a ChainVerifier error exposes when assembly could not
// resolve a predecessor — the unresolved hole's content address. The auditor matches it
// via errors.As, so it need NOT import the chain-walk package that produces it (the
// network/ ↔ pipeline/ layer rule: they never import each other — AGENTS.md). The
// composition root injects a ChainVerifier whose hole error satisfies this.
type HoleError interface {
	error
	UnresolvedHash() string
}

// HeadResolver loads a credential by content address from the LOCAL store — satisfied by
// *vcresolver.Service (ResolveVC). The chain is assembled in-process; slice-17g already
// fetched the predecessors. The Runner also uses it to check whether an unresolved hole
// has since appeared in the store.
type HeadResolver interface {
	ResolveVC(ctx context.Context, hash string) (*vc.PipelinePassCredential, error)
}

// ChainVerifier assembles a chain from head and returns its verdict — satisfied by a
// *chainwalk.ChainVerifier over a local-store resolver + vc.Verifier. A chain hole
// surfaces as a *chainwalk.UnresolvedPredecessorError.
type ChainVerifier interface {
	VerifyChain(ctx context.Context, head *vc.PipelinePassCredential) (*vc.VerifyResult, error)
}

// PoolLiveness reports whether a hash is still queued for resolution — the liveness signal
// for finalizing an Indeterminate-by-hole verdict. Satisfied by the shared *memstore.Pool.
type PoolLiveness interface {
	Has(hash string) bool
}

// Config is the node-level audit-runner tuning. All values are required and positive (no
// Go defaults); New rejects a non-positive value.
type Config struct {
	Interval    time.Duration // between drain ticks
	BatchSize   int           // max heads audited per tick
	MaxAttempts int           // backstop bound for a persistent NON-hole indeterminate
}

// Construction errors.
var (
	ErrNilDependency = errors.New("auditor: nil dependency")
	ErrBadConfig     = errors.New("auditor: config value must be positive")
)

// Runner drains the audit queue, verifies each head's chain, and records the verdict.
// Construct with New, run with Run.
type Runner struct {
	queue  AuditQueue
	head   HeadResolver
	cv     ChainVerifier
	status StatusStore
	pool   PoolLiveness
	cfg    Config
	logger *log.Logger
	now    func() time.Time
}

// Option configures a Runner.
type Option func(*Runner)

// WithLogger overrides the log destination (default log.Default()).
func WithLogger(l *log.Logger) Option {
	return func(r *Runner) {
		if l != nil {
			r.logger = l
		}
	}
}

// WithClock overrides the AuditedAt clock (default time.Now) for deterministic tests.
func WithClock(now func() time.Time) Option {
	return func(r *Runner) {
		if now != nil {
			r.now = now
		}
	}
}

// New validates dependencies and config and returns a ready Runner.
func New(q AuditQueue, head HeadResolver, cv ChainVerifier, status StatusStore, pool PoolLiveness, cfg Config, opts ...Option) (*Runner, error) {
	if q == nil || head == nil || cv == nil || status == nil || pool == nil {
		return nil, ErrNilDependency
	}
	if cfg.Interval <= 0 || cfg.BatchSize < 1 || cfg.MaxAttempts < 1 {
		return nil, fmt.Errorf("%w: %+v", ErrBadConfig, cfg)
	}
	r := &Runner{queue: q, head: head, cv: cv, status: status, pool: pool, cfg: cfg, logger: log.Default(), now: time.Now}
	for _, opt := range opts {
		opt(r)
	}
	return r, nil
}

// Run audits the queue every cfg.Interval until ctx is cancelled. A drain-tick error is
// logged and the loop continues (a degraded audit must not stop the node); Run returns nil
// on a clean ctx cancellation.
func (r *Runner) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := r.drainOnce(ctx); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				r.logger.Printf("auditor: drain tick: %v", err)
			}
		}
	}
}

// drainOnce audits up to BatchSize heads once. Factored out of Run so tests drive a single
// tick deterministically. A per-head failure is handled within auditOne; only a queue-list
// failure is returned.
func (r *Runner) drainOnce(ctx context.Context) error {
	cands, err := r.queue.ListNewest(r.cfg.BatchSize)
	if err != nil {
		return fmt.Errorf("list audit queue: %w", err)
	}
	for _, c := range cands {
		if ctx.Err() != nil {
			return nil
		}
		r.auditOne(ctx, c)
	}
	return nil
}

// auditOne audits one queued head: skip+dequeue if already terminal, else resolve the head,
// run VerifyChain, and record the verdict — dequeueing on a terminal or resolver-abandoned
// outcome, retaining (and for non-hole indeterminates, attempt-bounding) otherwise.
func (r *Runner) auditOne(ctx context.Context, c AuditCandidate) {
	// A head already holding a terminal verdict (immutable content → stable) is dequeued
	// without re-verifying — covers re-registration of a previously-audited head.
	if rec, ok := r.status.Get(c.HeadHash); ok && isTerminal(rec.Overall) {
		r.remove(c.HeadHash)
		return
	}

	head, err := r.head.ResolveVC(ctx, c.HeadHash)
	if err != nil {
		if isCtxErr(err) {
			return
		}
		// The head itself is gone (e.g. an in-memory store cleared on restart) — a stale
		// registration with nothing to audit; drop it.
		r.logger.Printf("auditor: dropping %s: head not resolvable: %v", c.HeadHash, err)
		r.remove(c.HeadHash)
		return
	}

	res, err := r.cv.VerifyChain(ctx, head)
	if err != nil {
		var hole HoleError
		switch {
		case isCtxErr(err):
			return // shutdown: record nothing, leave queued
		case errors.As(err, &hole):
			r.handleHole(ctx, c, hole.UnresolvedHash())
		default:
			// A non-hole verify/transport error (e.g. an unresolvable signer DID surfacing
			// as an error) — record Indeterminate and bound by the attempt backstop.
			if err := r.recordIndeterminate(c.HeadHash, "verify error: "+err.Error()); err != nil {
				return // keep queued, retry next tick
			}
			r.bumpOrDrop(c, "non-hole verify error")
		}
		return
	}

	// A complete chain: record the verdict verbatim (linear coverage only — D-17h-6). Only
	// advance queue state (dequeue/bump) once the verdict is durably recorded — a failed
	// write must not lose the audit by dequeuing without a record (Codex).
	if err := r.status.Put(c.HeadHash, AuditRecord{
		Overall:   res.Overall,
		Axes:      res.Axes,
		Notations: res.Notations,
		Scope:     AuditScope{LinearChain: true},
		AuditedAt: r.now(),
	}); err != nil {
		r.logger.Printf("auditor: %s: record verdict: %v", c.HeadHash, err)
		return // keep queued, retry next tick
	}
	switch res.Overall {
	case vc.ConfidenceVerified, vc.ConfidenceFailed:
		r.remove(c.HeadHash) // terminal
	default:
		// Assembled but Indeterminate (a non-hole reason) — bound by the attempt backstop.
		r.bumpOrDrop(c, "assembled but indeterminate")
	}
}

// handleHole records a synthetic Indeterminate for an assembly hole and decides liveness:
// retain while the hole may yet resolve (now in the store, or still queued in the pool),
// finalize and dequeue once the resolver has abandoned it (in neither). No attempt is
// burned while the hole is still being worked — a deep, legitimately-assembling chain is
// never wrongly dropped (D-17h-4).
func (r *Runner) handleHole(ctx context.Context, c AuditCandidate, holeHash string) {
	if err := r.recordIndeterminate(c.HeadHash, "unresolved predecessor "+holeHash); err != nil {
		return // status write failed — keep queued, retry next tick (do not advance state)
	}

	if _, err := r.head.ResolveVC(ctx, holeHash); err == nil {
		return // the predecessor appeared in the store; the next tick completes the chain
	} else if isCtxErr(err) {
		return
	}
	if r.pool.Has(holeHash) {
		return // the resolver is still working this hole; retry next tick, no attempt burned
	}
	// Absent from BOTH store and pool. This is usually an abandoned hole — but it can also be
	// the sub-tick window inside StoreVC between a fetched predecessor becoming visible (Put)
	// and its own predecessor being enqueued (pool.Add). Finalizing here on a single
	// observation would wrongly drop a still-completing chain (Codex P2). So bound it by the
	// attempt grace instead: the transient window bumps at most once (the next tick the hole
	// is queued again → no bump), while a genuinely abandoned hole accrues toward max-attempts.
	r.bumpOrDrop(c, "predecessor "+holeHash+" absent from store and pool")
}

// recordIndeterminate writes a synthetic Indeterminate record. Every axis is set EXPLICITLY
// to Indeterminate — the AxisResult zero value is ConfidenceFailed (fail-closed lattice),
// so leaving axes unset would wrongly read as Failed. It returns the store error so the
// caller can avoid advancing queue state (dequeue/bump) on a failed write.
func (r *Runner) recordIndeterminate(headHash, notation string) error {
	ind := vc.ConfidenceIndeterminate
	if err := r.status.Put(headHash, AuditRecord{
		Overall:   ind,
		Axes:      vc.AxisResult{DataIntegrity: ind, SignerAuthenticity: ind, ChainConsistency: ind},
		Notations: []string{notation},
		Scope:     AuditScope{LinearChain: true},
		AuditedAt: r.now(),
	}); err != nil {
		r.logger.Printf("auditor: %s: record indeterminate: %v", headHash, err)
		return err
	}
	return nil
}

// bumpOrDrop increments the head's attempt counter, or drops it once MaxAttempts is reached
// (the backstop for a persistent indeterminate that the pool-liveness signal cannot
// finalize — a non-hole verdict, or a hole absent from both store and pool).
func (r *Runner) bumpOrDrop(c AuditCandidate, reason string) {
	if c.Attempts+1 >= r.cfg.MaxAttempts {
		r.logger.Printf("auditor: dropping %s: exhausted %d audit attempts (%s)", c.HeadHash, r.cfg.MaxAttempts, reason)
		r.remove(c.HeadHash)
		return
	}
	if err := r.queue.IncrementAttempt(c.HeadHash); err != nil {
		r.logger.Printf("auditor: %s: increment attempt: %v", c.HeadHash, err)
	}
}

func (r *Runner) remove(headHash string) {
	if err := r.queue.Remove(headHash); err != nil {
		r.logger.Printf("auditor: %s: remove from queue: %v", headHash, err)
	}
}

func isTerminal(s vc.ConfidenceState) bool {
	return s == vc.ConfidenceVerified || s == vc.ConfidenceFailed
}

func isCtxErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
