package auditor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/provin-line/oss/network/pkg/services/vcresolver"
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

// ReceiptReader reads the emit-time consumed-set receipt for an aggregate head (slice-17o):
// the exact source content addresses the emitting node folded into the head's SourceCommitment.
// Satisfied by any ReceiptStore. Presence is the coverage gate — a head with no receipt
// (wrapped ErrNotFound) is audited linear-only (a downstream/non-emitting node), never
// falsely flipping the flag; any other error is a DAMAGED receipt, which fails the
// consumed-set verdict closed rather than downgrading coverage.
type ReceiptReader interface {
	Get(headHash string) ([]string, error)
}

// SourceCommitmentVerifier recomputes a credential's SourceCommitment over the gathered
// consumed sources — satisfied by *vc.Verifier. A narrow consumer-defined seam (mirrors
// ChainVerifier) so the auditor need not construct the verification engine.
type SourceCommitmentVerifier interface {
	VerifySourceCommitment(ctx context.Context, cred *vc.PipelinePassCredential, sources []*vc.PipelinePassCredential) (vc.ConfidenceState, error)
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
	// Source-commitment audit (slice-17o), enabled via WithSourceCommitment. Both nil (the
	// option unset) → linear-only audit, exactly the pre-17o behavior.
	receipts ReceiptReader
	scv      SourceCommitmentVerifier
	// Verdict-write counters behind VerdictCounts (P1-2 metrics): atomics because a metrics
	// surface polls them from a different goroutine than the drain loop.
	verdictVerified      atomic.Uint64
	verdictFailed        atomic.Uint64
	verdictIndeterminate atomic.Uint64
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

// WithSourceCommitment enables the consumed-set (SourceCommitment) audit step (slice-17o):
// for an aggregate head that has a local receipt, the runner gathers the consumed sources
// from the local store and records a DISTINCT source-commitment verdict alongside the linear
// one. Both args must be non-nil to take effect (a nil pair leaves the runner linear-only).
func WithSourceCommitment(receipts ReceiptReader, scv SourceCommitmentVerifier) Option {
	return func(r *Runner) {
		if receipts != nil && scv != nil {
			r.receipts = receipts
			r.scv = scv
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
	// A head already holding a FULLY terminal verdict (immutable content → stable) is dequeued
	// without re-verifying — covers re-registration of a previously-audited head. A terminal
	// linear verdict with a still-retryable source-commitment Indeterminate is NOT fully
	// terminal: it must be re-audited so the consumed-set verdict can resolve (slice-17o).
	// A DAMAGED prior verdict (non-ErrNotFound read error) falls through to a fresh audit:
	// re-verifying from evidence and overwriting the record is repair, not trust in the file.
	if rec, err := r.status.Get(c.HeadHash); err == nil && isTerminal(rec.Overall) && !scRetryable(rec) {
		r.remove(c.HeadHash)
		return
	} else if err != nil && !errors.Is(err, ErrNotFound) {
		r.logger.Printf("auditor: %s: damaged verdict record, re-auditing: %v", c.HeadHash, err)
	}

	head, err := r.head.ResolveVC(ctx, c.HeadHash)
	if err != nil {
		if isCtxErr(err) {
			return
		}
		// Only a DEFINITIVE miss (the head is not in the store) is a stale
		// registration to drop. Any other error — a damaged/tampered evidence
		// file, an unavailable store — must NOT be laundered into absence: the
		// head stays queued (attempt-bounded) so damage surfaces as retries and
		// logs instead of a silently vanished audit.
		if errors.Is(err, vcresolver.ErrNotFound) {
			r.logger.Printf("auditor: dropping %s: head not resolvable: %v", c.HeadHash, err)
			r.remove(c.HeadHash)
			return
		}
		r.logger.Printf("auditor: %s: head unreadable (damaged evidence?), retaining: %v", c.HeadHash, err)
		r.bumpOrDrop(c, "head unreadable")
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

	// A complete chain: build the verdict record. The linear verdict is verbatim from
	// VerifyChain; the source-commitment verdict (slice-17o) is folded into the SAME record so
	// a single Put lands both — never a linear write followed by a second source write, which a
	// failure between could leave terminal-linear-only and permanently lose (Codex spec #2,
	// D-17o-9). Only advance queue state once the verdict is durably recorded (Codex 17h).
	rec := AuditRecord{
		Overall:   res.Overall,
		Axes:      res.Axes,
		Notations: res.Notations,
		Scope:     AuditScope{LinearChain: true},
		AuditedAt: r.now(),
	}
	if abort := r.evaluateSourceCommitment(ctx, c.HeadHash, head, &rec); abort {
		return // ctx cancelled mid-evaluation: record nothing, leave queued
	}
	if err := r.recordVerdict(c.HeadHash, rec); err != nil {
		r.logger.Printf("auditor: %s: record verdict: %v", c.HeadHash, err)
		return // keep queued, retry next tick
	}
	switch {
	case isTerminal(res.Overall) && !scRetryable(rec):
		r.remove(c.HeadHash) // fully terminal: linear terminal AND consumed-set not retry-worthy
	case scRetryable(rec):
		// Linear terminal but the consumed-set verdict is a still-resolving Indeterminate
		// (incomplete receipt) — retain and re-audit, bounded by the attempt backstop so a
		// permanently-missing source eventually finalizes (slice-17o, Codex P2).
		r.bumpOrDrop(c, "source-commitment indeterminate (incomplete receipt)")
	default:
		// Assembled but linear-Indeterminate (a non-hole reason) — bound by the attempt backstop.
		r.bumpOrDrop(c, "assembled but indeterminate")
	}
}

// truncateForNote bounds a possibly-long/unsanitized string (e.g. a corrupt receipt entry)
// before it flows into a wire notation.
func truncateForNote(s string) string {
	const max = 80
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// evaluateSourceCommitment folds the DISTINCT consumed-set verdict into rec when this head
// is an aggregate emission with a local receipt (slice-17o). It returns true ONLY to signal
// a context cancellation mid-evaluation (the caller then records nothing and leaves the head
// queued). With the capability disabled or no receipt present, it leaves rec linear-only.
// Decision table (D-17o-6): no receipt → linear-only; corrupt receipt (an unreadable record
// or a malformed entry) → fail-closed Failed (no verifier call — damage must not silently
// downgrade the audit to linear-only); otherwise gather the resolvable subset and record the
// VerifySourceCommitment result (a missing source reduces the set → Indeterminate).
func (r *Runner) evaluateSourceCommitment(ctx context.Context, headHash string, head *vc.PipelinePassCredential, rec *AuditRecord) bool {
	if r.receipts == nil || r.scv == nil {
		return false // capability disabled → linear-only
	}
	consumed, err := r.receipts.Get(headHash)
	if errors.Is(err, ErrNotFound) {
		return false // no receipt → linear-only (downstream/non-emitting node)
	}
	if err != nil {
		// A receipt exists but cannot be read — fail closed on the consumed-set
		// verdict rather than presenting linear-only as intended coverage.
		rec.SourceCommitment = vc.ConfidenceFailed
		rec.Scope.SourceCommitmentEvaluated = true
		rec.SourceCommitmentNotations = []string{scLocus + ": unreadable receipt: " + truncateForNote(err.Error())}
		return false
	}
	// A malformed content address in the receipt is a corrupt receipt → fail-closed, no
	// verifier call.
	for _, h := range consumed {
		if !isContentAddress(h) {
			rec.SourceCommitment = vc.ConfidenceFailed
			rec.Scope.SourceCommitmentEvaluated = true
			rec.SourceCommitmentNotations = []string{scLocus + ": corrupt receipt entry " + truncateForNote(h)}
			return false
		}
	}
	// Gather the consumed sources from the local store; a ctx error aborts the whole tick.
	sources := make([]*vc.PipelinePassCredential, 0, len(consumed))
	unresolved := 0
	for _, h := range consumed {
		src, err := r.head.ResolveVC(ctx, h)
		if err != nil {
			if isCtxErr(err) {
				return true
			}
			unresolved++
			continue
		}
		sources = append(sources, src)
	}
	// Incomplete receipt: do NOT trust the verifier over a SUBSET (Codex P1, Claude Important).
	// The Merkle root is over the full set, and DerivedFrom is issuer-granular — so a partial
	// set can spuriously MATCH (false Verified) or, when a missing source shares an issuer with
	// a resolved one, spuriously MISMATCH (false Failed). Record Indeterminate without calling
	// the verifier and retain the head; the lifecycle (auditOne) re-audits until the missing
	// source arrives (bounded by the attempt backstop). At the emit locus this is normally
	// unreachable — every consumed source is stored locally before the head is enqueued — so
	// this is the defensive/degraded path (e.g. a source evicted from an in-memory store).
	if unresolved > 0 {
		rec.SourceCommitment = vc.ConfidenceIndeterminate
		rec.Scope.SourceCommitmentEvaluated = true
		rec.SourceCommitmentNotations = []string{fmt.Sprintf("%s: %d/%d consumed sources resolved (incomplete → indeterminate, retained)", scLocus, len(sources), len(consumed))}
		return false
	}
	state, err := r.scv.VerifySourceCommitment(ctx, head, sources)
	// The current verifier is pure-CPU and never returns a ctx error; this guard is defensive
	// for a future ctx-aware SourceCommitmentVerifier (leave queued, retry — never a verdict).
	if err != nil && isCtxErr(err) {
		return true
	}
	// A non-ctx verifier error (duplicate gathered source, hashing failure, or no commitment
	// on the head) is a fail-closed Failed — VerifySourceCommitment returns Failed in those
	// cases and the error is advisory; record it in the notation.
	rec.SourceCommitment = state
	rec.Scope.SourceCommitmentEvaluated = true
	note := fmt.Sprintf("%s: all %d consumed sources resolved", scLocus, len(consumed))
	if err != nil {
		note += "; verifier: " + err.Error()
	}
	rec.SourceCommitmentNotations = []string{note}
	return false
}

// scRetryable reports whether a recorded source-commitment verdict warrants another audit
// pass — an incomplete-receipt Indeterminate that may become terminal once the missing
// consumed source arrives (slice-17o). It keeps a terminal LINEAR verdict from prematurely
// finalizing (dequeuing) a still-resolving consumed-set verdict (Codex P2, Claude Important).
func scRetryable(rec AuditRecord) bool {
	return rec.Scope.SourceCommitmentEvaluated && rec.SourceCommitment == vc.ConfidenceIndeterminate
}

// scLocus names the audit locus in a source-commitment notation so a reader cannot mistake a
// self-audit verdict for independent relying-party (consume-locus) coverage (D-17o-6).
const scLocus = "source-commitment: self-audit (emit locus)"

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

// recordVerdict durably writes one verdict record and, on success, counts the write by its
// linear overall verdict — the single funnel every runner status.Put goes through, so the
// counters behind VerdictCounts stay exactly "successful verdict-record writes" with no
// per-call-site judgment. It returns the store error unchanged (a failed write counts
// nothing: no durable record, no verdict).
func (r *Runner) recordVerdict(headHash string, rec AuditRecord) error {
	if err := r.status.Put(headHash, rec); err != nil {
		return err
	}
	switch rec.Overall {
	case vc.ConfidenceVerified:
		r.verdictVerified.Add(1)
	case vc.ConfidenceFailed:
		r.verdictFailed.Add(1)
	default:
		// Indeterminate and any future/unknown state: "not verified, not failed"
		// must not vanish from the counts (mirrors the fail-closed lattice).
		r.verdictIndeterminate.Add(1)
	}
	return nil
}

// VerdictCounts returns the monotonic counts of durably recorded verdict WRITES keyed by
// "verified" | "failed" | "indeterminate" — the linear-chain overall verdict only (the
// distinct source-commitment verdict is not counted). It counts writes, not audited heads:
// a re-audit, a per-tick hole re-record, and an abandon finalization each count again.
// Every key is always present (zero-valued when never hit), so a metrics bridge can
// register a fixed label set; safe to call from a different goroutine than the drain loop.
func (r *Runner) VerdictCounts() map[string]uint64 {
	return map[string]uint64{
		"verified":      r.verdictVerified.Load(),
		"failed":        r.verdictFailed.Load(),
		"indeterminate": r.verdictIndeterminate.Load(),
	}
}

// recordIndeterminate writes a synthetic Indeterminate record. Every axis is set EXPLICITLY
// to Indeterminate — the AxisResult zero value is ConfidenceFailed (fail-closed lattice),
// so leaving axes unset would wrongly read as Failed. It returns the store error so the
// caller can avoid advancing queue state (dequeue/bump) on a failed write.
func (r *Runner) recordIndeterminate(headHash, notation string) error {
	ind := vc.ConfidenceIndeterminate
	if err := r.recordVerdict(headHash, AuditRecord{
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
// finalize — a non-hole verdict, or a hole absent from both store and pool). The drop is
// never silent: the abandon marker must land in the status store BEFORE the head leaves
// the queue, or the head stays queued — otherwise "gave up" would be a log line only,
// invisible to every GetAuditStatus consumer.
func (r *Runner) bumpOrDrop(c AuditCandidate, reason string) {
	if c.Attempts+1 >= r.cfg.MaxAttempts {
		if err := r.markAbandoned(c.HeadHash, reason); err != nil {
			r.logger.Printf("auditor: %s: mark abandoned: %v", c.HeadHash, err)
			return // keep queued, retry next tick (the marker must not be lost)
		}
		r.logger.Printf("auditor: dropping %s: exhausted %d audit attempts (%s)", c.HeadHash, r.cfg.MaxAttempts, reason)
		r.remove(c.HeadHash)
		return
	}
	if err := r.queue.IncrementAttempt(c.HeadHash); err != nil {
		r.logger.Printf("auditor: %s: increment attempt: %v", c.HeadHash, err)
	}
}

// markAbandoned finalizes the status record for a head the runner will not retry
// again. The note lands in the scope whose retry actually ran out: with a terminal
// linear verdict the exhausted retry is the consumed-set one, so the note goes to
// SourceCommitmentNotations; otherwise the linear scope. A head that never got a
// verdict written (e.g. unreadable from the first attempt) gets a synthesized
// Indeterminate — a consumer must find SOME record behind an abandoned head. A
// damaged existing record is an error (keep queued): auditOne's next tick re-audits
// and repairs it, and the abandon lands on the repaired record.
func (r *Runner) markAbandoned(headHash, reason string) error {
	rec, err := r.status.Get(headHash)
	if errors.Is(err, ErrNotFound) {
		ind := vc.ConfidenceIndeterminate
		rec = AuditRecord{
			Overall: ind,
			Axes:    vc.AxisResult{DataIntegrity: ind, SignerAuthenticity: ind, ChainConsistency: ind},
			Scope:   AuditScope{LinearChain: true},
		}
	} else if err != nil {
		return err
	}
	note := fmt.Sprintf("audit abandoned: exhausted %d attempts (%s)", r.cfg.MaxAttempts, reason)
	if isTerminal(rec.Overall) && scRetryable(rec) {
		rec.SourceCommitmentNotations = append(rec.SourceCommitmentNotations, note)
	} else {
		rec.Notations = append(rec.Notations, note)
	}
	rec.Abandoned = true
	rec.AuditedAt = r.now()
	return r.recordVerdict(headHash, rec)
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
