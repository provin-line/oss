package vcresolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/vc"
)

// ErrInvalidArgument is a malformed credential or content-address hash. The
// handler maps it to InvalidArgument; ErrNotFound (store.go) maps to NotFound.
var ErrInvalidArgument = errors.New("vcresolver: invalid argument")

// Service stores VCs by content address and queues unresolved previousCredential
// holes. The async batch resolver that drains the pool is a later slice; this
// service stores, serves, and enqueues.
//
// The store is the CONCRETE façade, not an interface: identity recomputation,
// write-once admission and canonical validation are enforced there, and taking
// an interface here would let a deployment wire in something that skips them.
// Storage choice is made at the backend seam (vcresolver.VariantBackend),
// which is below all of that.
type Service struct {
	store *VariantStore
	pool  Pool
	index successorIndex
}

// New returns a Service over store and pool.
func New(store *VariantStore, pool Pool) *Service {
	return &Service{store: store, pool: pool}
}

// StoreVCResult is the identity a submission was admitted under: the body
// address every successor links to, and the variant naming the exact signed
// form those bytes are. It is a struct rather than two strings so the promotion
// and evidence-view work (P0-1 slices B/C) can add what it learns without
// breaking every caller again.
type StoreVCResult struct {
	// BodyAddress is the content address of the proof-excluded body.
	BodyAddress string
	// WireVariantID names the exact wire bytes admitted — the key an evidence
	// path fetches with (admission.resolve-variant.exact).
	WireVariantID string
}

// StoreVC stores a submitted VC at its recomputed content address and, when the
// VC links a previousCredential the store does not already hold, enqueues that
// hole for the resolver (recording the referrer issuer so an empty upstream hint
// stays resolvable). It is fail-closed: the credential is strict-decoded and its
// previousCredential, if present, must be a well-formed content address — the
// typed accessor would otherwise silently coerce a malformed link to "" and
// admit a linked credential as a chain origin. The cryptographic proof is NOT
// verified here (content-addressed storage; verification is the auditor's job).
//
// assemblyDepth is the depth of THIS credential (the one being stored): 0 for a
// directly-received credential (ingress, or a wire submission), or the drained
// hole's depth when the batch resolver re-submits a fetched predecessor. A missing
// predecessor is enqueued at assemblyDepth+1, so a real hole is always >= 1; the
// resolver enforces a max-depth against it to bound assembly. A directly-received
// credential at depth 0 therefore resets its predecessor to depth 1 even if the
// credential was itself previously queued as a deeper hole.
func (s *Service) StoreVC(ctx context.Context, credential []byte, upstreamEndpoint string, assemblyDepth int) (StoreVCResult, error) {
	if err := ctx.Err(); err != nil {
		return StoreVCResult{}, err
	}
	if assemblyDepth < 0 {
		return StoreVCResult{}, fmt.Errorf("%w: assemblyDepth %d is negative", ErrInvalidArgument, assemblyDepth)
	}
	// Admission gate (canon.number.safe-integer) over the FULL wire document,
	// proof included. This is a body-as-SoT boundary: unknown members survive
	// into the stored canonical bytes, and the RFC 8785 re-serialization would
	// silently ROUND an unsafe integer at rest, storing bytes the original
	// signature never covered. Values beyond ±(2^53-1) belong in the string
	// domain, so this rejects loudly instead.
	//
	// It runs on the raw submission and not on the decoded credential because
	// by then the split has happened: gating only the body would let an unsafe
	// integer in a proof member through, and the variant id digests the whole
	// document — so a rounded proof would be admitted under an id naming bytes
	// nobody sent. The decode is lossless (json.Number), which the catalog
	// requires: the check has to see the literal, not a value already rounded
	// by parsing it.
	var doc any
	if err := canon.NewStrictDecoder(credential).Decode(&doc); err != nil {
		return StoreVCResult{}, fmt.Errorf("%w: decode credential: %v", ErrInvalidArgument, err)
	}
	if err := canon.AdmitSafeNumbers(doc); err != nil {
		return StoreVCResult{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	var cred vc.PipelinePassCredential
	// Delegates to PipelinePassCredential.UnmarshalJSON, which routes the
	// decode through canon.StrictDecoder (decoder-hygiene-exempt).
	if err := json.Unmarshal(credential, &cred); err != nil {
		return StoreVCResult{}, fmt.Errorf("%w: decode credential: %v", ErrInvalidArgument, err)
	}
	prev, hasPrev, err := rawPreviousCredential(cred.Body())
	if err != nil {
		return StoreVCResult{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	if hasPrev && !isContentAddress(prev) {
		return StoreVCResult{}, fmt.Errorf("%w: previousCredential %q is not a sha256:<hex> content address", ErrInvalidArgument, prev)
	}
	hash, variant, err := s.store.PutVariant(&cred)
	if err != nil {
		return StoreVCResult{}, err
	}
	// Maintain the forward index AFTER the durable put (a crash between the
	// two loses only the in-memory edge, which the next build re-derives).
	if hasPrev {
		s.index.add(prev, hash)
	}
	// Ordering is crash-safe for DURABLE stores: the next hole is queued
	// BEFORE the resolved hole is removed. A crash between the two leaves the
	// resolved hole queued — the batch resolver re-fetches it and the
	// idempotent Put/Add converge on replay. The reverse order would let a
	// crash permanently stall chain assembly (hole removed, successor hole
	// never queued) — re-resolution is the recovery rule, so no boot-repair
	// pass exists to paper over a wrong order.
	if hasPrev {
		switch _, err := s.store.Get(prev); {
		case err == nil:
			// Predecessor already held — no hole to queue.
		case errors.Is(err, ErrNotFound):
			if err := s.pool.Add(UnresolvedEntry{
				Hash:             prev,
				UpstreamEndpoint: upstreamEndpoint,
				ReferrerIssuer:   cred.Issuer(),
				AssemblyDepth:    assemblyDepth + 1,
			}); err != nil {
				return StoreVCResult{}, err
			}
		default:
			// A real store failure (not a miss) — propagate it rather than
			// silently dropping the chain hole.
			return StoreVCResult{}, err
		}
	}
	// Storing this VC resolves any queued hole for its own hash — an out-of-order
	// submission (a successor queued this predecessor before it arrived). Remove
	// is idempotent, so this is a no-op when the hash was never queued.
	if err := s.pool.Remove(hash); err != nil {
		return StoreVCResult{}, err
	}
	return StoreVCResult{BodyAddress: hash, WireVariantID: variant}, nil
}

// ResolveVC returns the VC held at a content address. The hash must be a
// well-formed content address (InvalidArgument otherwise); a well-formed miss is
// ErrNotFound.
func (s *Service) ResolveVC(ctx context.Context, hash string) (*vc.PipelinePassCredential, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !isContentAddress(hash) {
		return nil, fmt.Errorf("%w: hash %q is not a sha256:<hex> content address", ErrInvalidArgument, hash)
	}
	return s.store.Get(hash)
}

// ResolveVariant returns the EXACT canonical wire bytes of one variant —
// byte-for-byte what was admitted, which is what evidence means
// (admission.resolve-variant.exact).
//
// This is the fetch an auditor, a bundle exporter, or anything reproducing a
// verdict uses. ResolveVC cannot serve that purpose: it answers with SOME
// signed form of the body (the projection), and which one it picks can change
// as the set grows.
//
// A malformed address is InvalidArgument; a well-formed pair this node does
// not hold is ErrNotFound. Damage is neither — the store reports it as such,
// because "we hold nothing" and "what we hold is not what it claims to be" are
// different facts about provenance.
func (s *Service) ResolveVariant(ctx context.Context, bodyAddress, wireVariantID string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.store.GetVariant(bodyAddress, wireVariantID)
}

// ListVariants returns up to limit variant ids of bodyAddress in lexicographic
// order strictly after fromExclusive, plus whether more remain.
//
// The cursor is a plain variant id: opaque continuation tokens are the
// handler's concern, matching ListSuccessors. An unknown body is an empty page,
// never an error — holding no variants is a normal answer, not a claim that
// none exist anywhere.
//
// Consistency is per-call: a variant admitted between two pages, sorting before
// the cursor, is not observed by that iteration. Every page is exact as of its
// own call and the set only grows, so a caller needing a complete snapshot
// re-lists until nothing new appears, or works from an evidence view that
// commits its spine (P0-1 slice B).
func (s *Service) ListVariants(ctx context.Context, bodyAddress, fromExclusive string, limit int) ([]string, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if limit <= 0 {
		return nil, false, fmt.Errorf("%w: limit %d is not positive", ErrInvalidArgument, limit)
	}
	// One extra: the store's full-page rule makes a short page mean exhausted,
	// so asking for limit+1 answers "is there more" without a second call and
	// without claiming more when the set ends exactly on the boundary.
	page, err := s.store.ListVariantIDs(bodyAddress, fromExclusive, limit+1)
	if err != nil {
		return nil, false, err
	}
	if len(page) > limit {
		return page[:limit], true, nil
	}
	return page, false, nil
}

// rawPreviousCredential reads previousCredential from the credential body
// WITHOUT the lossy typed accessor: a present-but-non-string link, or a non-
// object credentialSubject, is an error rather than a silent "". An absent
// subject or absent link returns ("", false, nil).
func rawPreviousCredential(body map[string]any) (prev string, present bool, err error) {
	subRaw, ok := body["credentialSubject"]
	if !ok {
		return "", false, nil
	}
	sub, ok := subRaw.(map[string]any)
	if !ok {
		return "", false, fmt.Errorf("credentialSubject is not an object")
	}
	pv, ok := sub["previousCredential"]
	if !ok || pv == nil {
		// A JSON null is a conformant chain origin, equivalent to omission
		// (credential.subject.previous-credential).
		return "", false, nil
	}
	s, ok := pv.(string)
	if !ok {
		return "", false, fmt.Errorf("previousCredential is not a string")
	}
	return s, true, nil
}

// isContentAddress delegates to the exported grammar predicate — the one
// implementation of the "sha256:<64 lowercase hex>" content-address syntax
// (vc.IsContentAddress), converged from the per-service copies.
func isContentAddress(s string) bool { return vc.IsContentAddress(s) }
