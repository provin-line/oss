package vcresolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/provin-line/oss/vc"
)

// ErrInvalidArgument is a malformed credential or content-address hash. The
// handler maps it to InvalidArgument; ErrNotFound (store.go) maps to NotFound.
var ErrInvalidArgument = errors.New("vcresolver: invalid argument")

// Service stores VCs by content address and queues unresolved previousCredential
// holes. The async batch resolver that drains the pool is a later slice; this
// service stores, serves, and enqueues.
type Service struct {
	store Store
	pool  Pool
}

// New returns a Service over store and pool.
func New(store Store, pool Pool) *Service {
	return &Service{store: store, pool: pool}
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
func (s *Service) StoreVC(ctx context.Context, credential []byte, upstreamEndpoint string, assemblyDepth int) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if assemblyDepth < 0 {
		return "", fmt.Errorf("%w: assemblyDepth %d is negative", ErrInvalidArgument, assemblyDepth)
	}
	var cred vc.PipelinePassCredential
	if err := json.Unmarshal(credential, &cred); err != nil {
		return "", fmt.Errorf("%w: decode credential: %v", ErrInvalidArgument, err)
	}
	prev, hasPrev, err := rawPreviousCredential(cred.Body())
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	if hasPrev && !isContentAddress(prev) {
		return "", fmt.Errorf("%w: previousCredential %q is not a sha256:<hex> content address", ErrInvalidArgument, prev)
	}
	hash, err := cred.Hash()
	if err != nil {
		return "", fmt.Errorf("%w: hash credential: %v", ErrInvalidArgument, err)
	}
	if err := s.store.Put(hash, &cred); err != nil {
		return "", err
	}
	// Storing this VC resolves any queued hole for its own hash — an out-of-order
	// submission (a successor queued this predecessor before it arrived). Remove
	// is idempotent, so this is a no-op when the hash was never queued.
	if err := s.pool.Remove(hash); err != nil {
		return "", err
	}
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
				return "", err
			}
		default:
			// A real store failure (not a miss) — propagate it rather than
			// silently dropping the chain hole.
			return "", err
		}
	}
	return hash, nil
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
	if !ok {
		return "", false, nil
	}
	s, ok := pv.(string)
	if !ok {
		return "", false, fmt.Errorf("previousCredential is not a string")
	}
	return s, true, nil
}

// isContentAddress reports whether s is a "sha256:<64 lowercase hex>" address —
// the form jcs.Hash produces and previousCredential links carry.
func isContentAddress(s string) bool {
	const prefix = "sha256:"
	if len(s) != len(prefix)+64 || s[:len(prefix)] != prefix {
		return false
	}
	for _, r := range s[len(prefix):] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}
