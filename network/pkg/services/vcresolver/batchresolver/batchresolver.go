// Package batchresolver drains the vcresolver unresolved pool: a background Runner
// periodically lists queued predecessor holes, fetches each missing credential from a
// peer's VCResolverService, verifies its content address, and re-submits it through the
// local StoreVC seam — which fills the hole and enqueues the next-deeper predecessor.
// Over successive ticks this assembles each consumed chain to its origin, so the local
// store accumulates complete, resolvable chains for the async audit path (the auditor —
// a later slice — verifies proofs and chain structure; this package only ASSEMBLES).
//
// Trust boundary: the Runner verifies ONLY that a fetched credential's content address
// equals the requested hash (a peer cannot substitute a body); it does NOT verify L1
// proofs or chain structure. A configured max-depth bounds assembly against an
// adversarial peer serving an arbitrarily long fabricated chain; every outbound fetch
// passes an SSRF guard.
package batchresolver

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/vc"
)

// Pool is the drain-queue seam (satisfied by *memstore.Pool): the Runner lists
// newest-first, removes on success or terminal drop, and bumps the retry counter on a
// transient failure. Redeclared here so the dependency points inward.
type Pool interface {
	ListNewest(n int) ([]vcresolver.UnresolvedEntry, error)
	// Get returns the live entry at hash and whether it is still queued — used to re-read
	// an entry's current AssemblyDepth (an earlier entry in the same drain snapshot may
	// have lowered it via keep-min, or resolved it) before acting on a stale snapshot copy.
	Get(hash string) (vcresolver.UnresolvedEntry, bool)
	Remove(hash string) error
	IncrementRetry(hash string) error
}

// Submitter re-submits a fetched predecessor (satisfied by *vcresolver.Service):
// StoreVC fills the entry's hole and enqueues the next predecessor at assemblyDepth+1.
type Submitter interface {
	StoreVC(ctx context.Context, credential []byte, upstreamEndpoint string, assemblyDepth int) (vcresolver.StoreVCResult, error)
}

// Fetcher fetches a credential by content address from a specific peer endpoint
// (satisfied by a vcresolver/client built per endpoint over the SSRF-guarded HTTP
// client, size-bounded by max-credential-size).
type Fetcher interface {
	Fetch(ctx context.Context, endpoint, contentAddress string) (*vc.PipelinePassCredential, error)
}

// DIDResolver derives a peer endpoint from an empty-hint entry's ReferrerIssuer
// (satisfied by *didresolver.Resolver).
type DIDResolver interface {
	Resolve(ctx context.Context, didStr string) (*did.DIDDocument, error)
}

// Guard rejects an SSRF-unsafe endpoint before any outbound fetch (satisfied by
// *core.URLGuard).
type Guard interface {
	CheckURL(ctx context.Context, raw string) error
}

// Config holds the node-level batch-resolver tuning. All values are required and must
// be positive (no Go-side defaults); New rejects a non-positive value.
type Config struct {
	Interval   time.Duration // between drain ticks
	BatchSize  int           // max entries drained per tick
	MaxRetries int           // transient-failure retries before dropping a hole
	MaxDepth   int           // assembly depth bound (drop a hole at or beyond this)
}

// Construction errors.
var (
	ErrNilDependency = errors.New("batchresolver: nil dependency")
	ErrBadConfig     = errors.New("batchresolver: config value must be positive")
)

const vcResolverServiceType = "VCResolver"

// Runner drains the pool. Construct with New, run with Run.
type Runner struct {
	pool   Pool
	sub    Submitter
	fetch  Fetcher
	did    DIDResolver
	guard  Guard
	cfg    Config
	logger *log.Logger
}

// Option configures a Runner.
type Option func(*Runner)

// WithLogger overrides the destination for truncation/error logs (default log.Default()).
func WithLogger(l *log.Logger) Option {
	return func(r *Runner) {
		if l != nil {
			r.logger = l
		}
	}
}

// New validates dependencies and config and returns a ready Runner.
func New(pool Pool, sub Submitter, fetch Fetcher, didResolver DIDResolver, guard Guard, cfg Config, opts ...Option) (*Runner, error) {
	if pool == nil || sub == nil || fetch == nil || didResolver == nil || guard == nil {
		return nil, ErrNilDependency
	}
	if cfg.Interval <= 0 || cfg.BatchSize < 1 || cfg.MaxRetries < 1 || cfg.MaxDepth < 1 {
		return nil, fmt.Errorf("%w: %+v", ErrBadConfig, cfg)
	}
	r := &Runner{pool: pool, sub: sub, fetch: fetch, did: didResolver, guard: guard, cfg: cfg, logger: log.Default()}
	for _, opt := range opts {
		opt(r)
	}
	return r, nil
}

// Run drains the pool every cfg.Interval until ctx is cancelled. A drain-tick error is
// logged and the loop continues (a hostile or unreachable peer must not stop the node);
// Run returns nil on a clean ctx cancellation.
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
				r.logger.Printf("batchresolver: drain tick: %v", err)
			}
		}
	}
}

// drainOnce drains up to BatchSize entries once. Factored out of Run so tests drive a
// single tick deterministically. A per-entry failure is handled within resolveEntry
// (log-and-continue); only a pool-listing failure is returned.
func (r *Runner) drainOnce(ctx context.Context) error {
	entries, err := r.pool.ListNewest(r.cfg.BatchSize)
	if err != nil {
		return fmt.Errorf("list pool: %w", err)
	}
	for _, e := range entries {
		if ctx.Err() != nil {
			return nil
		}
		r.resolveEntry(ctx, e)
	}
	return nil
}

// resolveEntry resolves one queued hole: enforce the depth bound, then try each candidate
// endpoint (hint, then issuer-derived) behind the SSRF guard, fetch + content-address
// verify + re-submit. Outcomes drive the pool: success removes the hole (via StoreVC), a
// content-address mismatch / guard rejection / terminal RPC error drops it, a definitive
// miss or exhausted connectivity retries it (dropping past MaxRetries).
func (r *Runner) resolveEntry(ctx context.Context, e vcresolver.UnresolvedEntry) {
	// Re-read the live entry: an earlier entry in this same drain snapshot may have resolved
	// this hole (removed it) or lowered its AssemblyDepth via keep-min. Acting on the stale
	// snapshot copy could wrongly drop a now-shallow hole or re-fetch a resolved one (Codex P2).
	live, ok := r.pool.Get(e.Hash)
	if !ok {
		return // already resolved/removed earlier this tick
	}
	e = live

	if e.AssemblyDepth >= r.cfg.MaxDepth {
		r.logger.Printf("batchresolver: dropping %s: assembly depth %d >= max-depth %d (truncated)", e.Hash, e.AssemblyDepth, r.cfg.MaxDepth)
		r.remove(e.Hash)
		return
	}

	// Try the caller-supplied hint first; derive the issuer endpoint LAZILY — only when the
	// hint is absent or unreachable — so a healthy hint never triggers a DID resolution.
	tried := false
	if e.UpstreamEndpoint != "" {
		tried = true
		if done := r.tryEndpoint(ctx, e, e.UpstreamEndpoint); done {
			return // resolved, dropped, or a definitive miss/retry — fate decided
		}
		// connection error on the hint → fall through to the issuer-derived endpoint
	}
	if e.ReferrerIssuer != "" {
		ep, err := r.deriveIssuerEndpoint(ctx, e.ReferrerIssuer)
		switch {
		case err != nil:
			r.logger.Printf("batchresolver: %s: issuer %q endpoint derivation: %v", e.Hash, e.ReferrerIssuer, err)
		case ep != "" && ep != e.UpstreamEndpoint:
			tried = true
			if done := r.tryEndpoint(ctx, e, ep); done {
				return
			}
		}
	}
	if !tried {
		r.logger.Printf("batchresolver: %s: no fetch endpoint (no hint, issuer derivation unavailable)", e.Hash)
	}
	// No endpoint resolved it (none usable, or every attempt was a connection error).
	r.retryOrDrop(e)
}

// tryEndpoint attempts one endpoint. It returns done=true when the entry's fate is decided
// — resolved (stored), terminally dropped (SSRF / content mismatch / terminal RPC error),
// or a definitive miss/local-error that retries the entry without trying elsewhere — and
// done=false only on a connection error, signalling the caller to try the next endpoint.
func (r *Runner) tryEndpoint(ctx context.Context, e vcresolver.UnresolvedEntry, endpoint string) (done bool) {
	if err := r.guard.CheckURL(ctx, endpoint); err != nil {
		// An SSRF-unsafe endpoint is actively suspicious — terminal drop (D-17g-8).
		r.logger.Printf("batchresolver: dropping %s: endpoint %q rejected by SSRF guard: %v", e.Hash, endpoint, err)
		r.remove(e.Hash)
		return true
	}
	cred, err := r.fetch.Fetch(ctx, endpoint, e.Hash)
	if err != nil {
		switch classify(err) {
		case catMiss:
			// The endpoint answered "I do not hold it" — retry later, do not try elsewhere.
			r.retryOrDrop(e)
			return true
		case catTerminal:
			r.logger.Printf("batchresolver: dropping %s: terminal fetch error from %q: %v", e.Hash, endpoint, err)
			r.remove(e.Hash)
			return true
		default: // catConnection — let the caller try the next endpoint.
			return false
		}
	}
	// Never trust the peer: the fetched body must hash to the requested address (D-17g-11).
	if got, herr := cred.Hash(); herr != nil || got != e.Hash {
		r.logger.Printf("batchresolver: dropping %s: peer %q served a mismatched body (got %q, err %v)", e.Hash, endpoint, got, herr)
		r.remove(e.Hash)
		return true
	}
	b, merr := cred.MarshalJSON()
	if merr != nil {
		// A local encode failure is not the endpoint's fault — retry the entry, no fallback.
		r.logger.Printf("batchresolver: %s: marshal fetched credential: %v", e.Hash, merr)
		r.retryOrDrop(e)
		return true
	}
	// Re-submit at this hole's depth: StoreVC fills the hole and enqueues the next-deeper
	// predecessor at AssemblyDepth+1 (D-17g-5/D-17g-12).
	if _, serr := r.sub.StoreVC(ctx, b, e.UpstreamEndpoint, e.AssemblyDepth); serr != nil {
		r.logger.Printf("batchresolver: %s: store fetched predecessor: %v", e.Hash, serr)
		r.retryOrDrop(e)
		return true
	}
	return true // resolved
}

// deriveIssuerEndpoint resolves issuer's DID document and returns its single
// #vc-resolver VCResolver service endpoint, failing closed on zero or multiple
// matches. The id must be exactly "#vc-resolver" or issuer+"#vc-resolver" —
// another URI merely ending in the fragment is someone else's advertisement
// and must be ignored, never captured or counted into a false ambiguity (the
// same exact-id rule the bundle exporter applies).
func (r *Runner) deriveIssuerEndpoint(ctx context.Context, issuer string) (string, error) {
	doc, err := r.did.Resolve(ctx, issuer)
	if err != nil {
		return "", fmt.Errorf("resolve DID: %w", err)
	}
	if doc == nil {
		return "", errors.New("nil DID document")
	}
	var found string
	var n int
	for _, s := range doc.Service() {
		if s.Type == vcResolverServiceType && (s.ID == "#vc-resolver" || s.ID == issuer+"#vc-resolver") {
			found = s.ServiceEndpoint
			n++
		}
	}
	if n != 1 {
		return "", fmt.Errorf("want exactly one #vc-resolver %s service, got %d", vcResolverServiceType, n)
	}
	if found == "" {
		return "", errors.New("#vc-resolver service has empty endpoint")
	}
	return found, nil
}

// retryOrDrop increments the hole's retry counter, or removes it once MaxRetries is reached.
func (r *Runner) retryOrDrop(e vcresolver.UnresolvedEntry) {
	if e.RetryCount >= r.cfg.MaxRetries {
		r.logger.Printf("batchresolver: dropping %s: exhausted %d retries", e.Hash, r.cfg.MaxRetries)
		r.remove(e.Hash)
		return
	}
	if err := r.pool.IncrementRetry(e.Hash); err != nil {
		r.logger.Printf("batchresolver: %s: increment retry: %v", e.Hash, err)
	}
}

func (r *Runner) remove(hash string) {
	if err := r.pool.Remove(hash); err != nil {
		r.logger.Printf("batchresolver: %s: remove from pool: %v", hash, err)
	}
}

// category classifies a fetch error to decide fallback/retry/terminal handling.
type category int

const (
	catConnection category = iota // unreachable/transient — try the next endpoint, then retry
	catMiss                       // the endpoint answered NotFound — retry the entry, no fallback
	catTerminal                   // not fixable by retrying with the same inputs — drop
)

// classify maps a fetch error to its handling category by Connect code: NotFound is a
// definitive miss; PermissionDenied / InvalidArgument / ResourceExhausted (size cap) are
// terminal; everything else (transport, Unavailable, deadline, unknown) is connectivity.
func classify(err error) category {
	switch connect.CodeOf(err) {
	case connect.CodeNotFound:
		return catMiss
	case connect.CodePermissionDenied, connect.CodeInvalidArgument, connect.CodeResourceExhausted:
		return catTerminal
	default:
		return catConnection
	}
}
