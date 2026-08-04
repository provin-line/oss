// Package cache bounds the cost of repeated DID document resolution: a
// decorator over any resolver.Resolver that serves recently resolved documents
// from memory instead of re-resolving them. Chain verification resolves the
// same small set of documents once per credential — one signer-authenticity
// lookup plus one per controller-chain hop, so 4·depth resolutions against a
// handful of distinct DIDs at typical hierarchy depth — and against the
// production HTTP resolver each of those is a real network round trip. The
// cache turns all but the first into local reads.
//
// # Freshness contract
//
// Every entry expires a fixed TTL after the resolution that filled it. Expiry
// is absolute: a hit never extends an entry's life, and an entry at or past
// its deadline is never served — there is no serve-stale-on-error. The TTL is
// therefore the exact upper bound on how long a decision can be made against a
// document the owning registry has since changed.
//
// Choosing the TTL is an operational freshness decision, not (today) a key-
// rotation one: the current did:dplaax method defines no key rotation, and
// public resolution carries no revocation signal. The moment either is added,
// this bound becomes security-relevant — a cached document would extend
// acceptance of superseded key material for up to the TTL — so a deployment
// choosing a long TTL is choosing its exposure window in advance. DefaultTTL
// is a provisional deployment default, deliberately short relative to
// registry-document change cadence; deployments with stricter freshness
// requirements lower it or keep the resolver uncached (the decorator is
// opt-in composition — the uncached path is the absence of this package).
//
// # Memory contract
//
// Resolution can be driven by unauthenticated input (an inbound proof's signer
// DID is resolved before its signature is checked), so cache keys are
// attacker-controllable and the cache must be bounded in BOTH entries and
// bytes: an entry-count bound alone retains unbounded memory when the wrapped
// resolver serves large documents. Admission never breaks resolution: a
// document that cannot be canonically serialized or that exceeds the byte
// budget is returned to the caller uncached, and eviction is LRU. The bounds
// cap retention only — they do not promise a hit rate under adversarial churn,
// and the wrapped resolver's own admission control (e.g. the production
// resolver's concurrency bound) remains the resource ceiling for misses.
//
// # What callers may assume
//
// Documents returned on a hit are freshly parsed per call: no *did.DIDDocument
// is ever shared between callers, so a caller mutating its copy (for example
// via UnmarshalJSON) cannot poison later resolutions. Errors — including the
// definitive resolver.ErrNotFound — are never cached: absence can become
// presence at registration time, and a cached miss would suppress a newly
// issued identity for a full TTL.
package cache

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/resolver"
)

// Defaults applied by New when the corresponding Config field is zero.
const (
	// DefaultTTL is a provisional deployment default (see the package comment:
	// an operational freshness bound, not a rotation-derived one).
	DefaultTTL = 60 * time.Second
	// DefaultMaxEntries bounds the number of cached documents.
	DefaultMaxEntries = 1024
	// DefaultMaxBytes bounds total retained document bytes. The production
	// resolver caps one document at 1 MiB, so the default admits at least 16
	// worst-case documents and thousands of typical ones.
	DefaultMaxBytes = 16 << 20

	// hitParseSlots bounds concurrent hit-path parses. The bare resolver holds
	// its 64-slot admission semaphore through fetch AND parse, so the
	// pre-signature, attacker-drivable resolution work was capped at 64
	// concurrent worst-case parses; a cache hit that parsed unboundedly would
	// RAISE that pre-authentication ceiling exactly where deployments enable
	// the cache. Unlike the network semaphore this one BLOCKS instead of
	// failing fast: the guarded work is a local parse with bounded completion
	// time — no remote party can pin a holder — so waiting is bounded, and a
	// fail-fast here would only push traffic back onto the network path the
	// cache exists to relieve.
	hitParseSlots = 64
)

var (
	// ErrMissingResolver is returned by New when next is nil.
	ErrMissingResolver = errors.New("cache: next resolver is required")
	// ErrInvalidConfig is returned by New for negative bounds.
	ErrInvalidConfig = errors.New("cache: invalid config")
)

// Config bounds the cache. Zero fields take the package defaults; negative
// fields are rejected. There is no "unbounded" setting on purpose — an
// unbounded cache keyed by attacker-controllable input is a memory
// amplification primitive.
type Config struct {
	// TTL is the absolute lifetime of an entry from the resolution that
	// filled it. Hits do not refresh it.
	TTL time.Duration
	// MaxEntries bounds how many documents are retained.
	MaxEntries int
	// MaxBytes bounds the total canonical bytes retained; a single document
	// larger than this is served uncached.
	MaxBytes int64
}

// Resolver is the caching decorator. Construct with New.
type Resolver struct {
	next       resolver.Resolver
	ttl        time.Duration
	maxEntries int
	maxBytes   int64

	// now is the clock; a test may substitute it to cross TTL boundaries.
	now func() time.Time

	// parseSem bounds concurrent hit-path parses (see hitParseSlots).
	parseSem chan struct{}

	// mu covers only the map/LRU bookkeeping below. Underlying resolution,
	// serialization, and parsing all happen outside it, so the lock cannot
	// serialize the synchronous verification path around network or parse work.
	mu      sync.Mutex
	lru     *list.List // front = most recently used; values are *entry
	entries map[string]*list.Element
	bytes   int64
}

// entry is one cached document: canonical bytes, never a parsed object, so a
// hit can hand every caller its own freshly parsed copy.
type entry struct {
	key     string
	raw     []byte
	expires time.Time
}

var _ resolver.Resolver = (*Resolver)(nil)

// New returns a caching decorator over next. Zero Config fields take the
// package defaults; negative fields return ErrInvalidConfig.
func New(next resolver.Resolver, cfg Config) (*Resolver, error) {
	if next == nil {
		return nil, ErrMissingResolver
	}
	if cfg.TTL < 0 || cfg.MaxEntries < 0 || cfg.MaxBytes < 0 {
		return nil, fmt.Errorf("%w: TTL=%v MaxEntries=%d MaxBytes=%d (negative bounds)",
			ErrInvalidConfig, cfg.TTL, cfg.MaxEntries, cfg.MaxBytes)
	}
	r := &Resolver{
		next:       next,
		ttl:        cfg.TTL,
		maxEntries: cfg.MaxEntries,
		maxBytes:   cfg.MaxBytes,
		now:        time.Now,
		parseSem:   make(chan struct{}, hitParseSlots),
		lru:        list.New(),
		entries:    make(map[string]*list.Element),
	}
	if r.ttl == 0 {
		r.ttl = DefaultTTL
	}
	if r.maxEntries == 0 {
		r.maxEntries = DefaultMaxEntries
	}
	if r.maxBytes == 0 {
		r.maxBytes = DefaultMaxBytes
	}
	return r, nil
}

// Resolve serves a fresh (within TTL) cached document when one exists and
// delegates to next otherwise. Every hit returns a newly parsed document; a
// miss returns next's result unchanged. Cache admission is best-effort and
// never converts a successful resolution into an error.
func (r *Resolver) Resolve(ctx context.Context, didStr string) (*did.DIDDocument, error) {
	if raw, ok := r.lookup(didStr); ok {
		// Parse under the hit bound; honor cancellation while waiting.
		select {
		case r.parseSem <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		doc := &did.DIDDocument{}
		err := doc.UnmarshalJSON(raw)
		<-r.parseSem
		if err == nil {
			return doc, nil
		}
		// Stored bytes that no longer parse cannot serve anyone; drop the
		// entry and resolve fresh. (They were produced by MarshalJSON on
		// admission, so this is defensive, not an expected path.)
		r.remove(didStr)
	}

	doc, err := r.next.Resolve(ctx, didStr)
	if err != nil || doc == nil {
		return doc, err
	}
	r.admit(didStr, doc)
	return doc, nil
}

// lookup returns the cached canonical bytes when present and fresh. The
// returned slice is never mutated after admission, so reading it outside the
// lock is safe.
func (r *Resolver) lookup(didStr string) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	elem, ok := r.entries[didStr]
	if !ok {
		return nil, false
	}
	e := elem.Value.(*entry)
	if !r.now().Before(e.expires) {
		r.dropLocked(elem)
		return nil, false
	}
	r.lru.MoveToFront(elem)
	return e.raw, true
}

// admit stores doc's canonical bytes under the bounds. Serialization failure,
// over-budget documents, and documents that cannot round-trip
// canonicalization are silently non-cacheable: the caller already holds a
// successful resolution and must keep it.
func (r *Resolver) admit(didStr string, doc *did.DIDDocument) {
	// A number outside ±(2^53−1) does not survive RFC 8785 (binary64 rounds
	// it), so a hit would return a numerically different body than the miss
	// did. Conforming registries reject such documents at registration
	// (didregistry runs the same gate), but resolution may face registries
	// that never ran it.
	if err := canon.AdmitSafeNumbers(doc.Body()); err != nil {
		return
	}
	raw, err := doc.MarshalJSON()
	if err != nil || int64(len(raw)) > r.maxBytes {
		return
	}
	expires := r.now().Add(r.ttl)

	r.mu.Lock()
	defer r.mu.Unlock()
	if elem, ok := r.entries[didStr]; ok {
		// Concurrent misses for one key: last fill wins, budget stays exact.
		e := elem.Value.(*entry)
		r.bytes += int64(len(raw)) - int64(len(e.raw))
		e.raw, e.expires = raw, expires
		r.lru.MoveToFront(elem)
	} else {
		elem := r.lru.PushFront(&entry{key: didStr, raw: raw, expires: expires})
		r.entries[didStr] = elem
		r.bytes += int64(len(raw))
	}
	for (len(r.entries) > r.maxEntries || r.bytes > r.maxBytes) && r.lru.Len() > 0 {
		r.dropLocked(r.lru.Back())
	}
}

// remove deletes one key if present.
func (r *Resolver) remove(didStr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if elem, ok := r.entries[didStr]; ok {
		r.dropLocked(elem)
	}
}

// dropLocked removes an element and its accounting. Caller holds mu.
func (r *Resolver) dropLocked(elem *list.Element) {
	e := elem.Value.(*entry)
	r.lru.Remove(elem)
	delete(r.entries, e.key)
	r.bytes -= int64(len(e.raw))
}
