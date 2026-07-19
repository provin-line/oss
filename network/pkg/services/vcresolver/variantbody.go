package vcresolver

import (
	"context"
	"fmt"
	"sync"

	"github.com/provin-line/oss/vc"
)

// variantIndex is the in-memory wire-variant-id -> body-address reverse
// lookup ResolveVariantBody needs: a caller holding only a variant id (no
// body address) cannot otherwise locate it, because VariantBackend is keyed
// strictly by (bodyHex, variantHex) — see variantstore.go's file doc — and
// carries no reverse index of its own. Built lazily on first use by scanning
// the store (boot cost zero; the first ResolveVariantBody call pays
// O(store)) and maintained by StoreVC's put path afterwards. In-memory
// only — a restart rebuilds from the store; mirrors successorIndex exactly
// (same file's rationale in successors.go applies here verbatim: set
// semantics make a doubly-observed edge harmless, and before the first
// build, add is a no-op because the store itself is the source of truth the
// build reads).
type variantIndex struct {
	mu    sync.Mutex
	built bool
	m     map[string]string // wire variant id -> body address
}

// add records wireVariantID -> bodyAddress if the index is materialized.
func (ix *variantIndex) add(wireVariantID, bodyAddress string) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if !ix.built {
		return
	}
	ix.m[wireVariantID] = bodyAddress
}

// lookup returns the body address wireVariantID belongs to, and whether it
// was found. It builds the index from store on first use.
func (ix *variantIndex) lookup(store *VariantStore, wireVariantID string) (bodyAddress string, ok bool, err error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if !ix.built {
		if err := ix.build(store); err != nil {
			return "", false, err
		}
	}
	bodyAddress, ok = ix.m[wireVariantID]
	return bodyAddress, ok, nil
}

// build scans the whole store: every held body's every held variant becomes
// an entry. A malformed link elsewhere in the store (e.g. previousCredential)
// is not this index's concern — it only reads addresses ListHashes and
// ListVariantIDs already validated as content addresses / wire variant ids.
func (ix *variantIndex) build(store *VariantStore) error {
	m := make(map[string]string)
	cursor := ""
	for {
		hashes, err := store.ListHashes(cursor, indexBuildPage)
		if err != nil {
			return fmt.Errorf("vcresolver: variant index build: %w", err)
		}
		if len(hashes) == 0 {
			break
		}
		for _, h := range hashes {
			vcursor := ""
			for {
				ids, err := store.ListVariantIDs(h, vcursor, indexBuildPage)
				if err != nil {
					return fmt.Errorf("vcresolver: variant index build: body %s: %w", h, err)
				}
				if len(ids) == 0 {
					break
				}
				for _, id := range ids {
					m[id] = h
				}
				vcursor = ids[len(ids)-1]
				if len(ids) < indexBuildPage {
					break
				}
			}
		}
		cursor = hashes[len(hashes)-1]
		if len(hashes) < indexBuildPage {
			break
		}
	}
	ix.m = m
	ix.built = true
	return nil
}

// ResolveVariantBody proves wireVariantID is admitted in the local store and
// returns the body address of the credential those exact bytes decode to —
// the read an admission gate needs when it holds only a variant id, with no
// body address alongside it (e.g. RegisterEvidence's wire request: the
// documented value of head_variant_address is the WIRE variant StoreVC
// returns, not a body content address, so the registering party never
// carries a body address to pair with it).
//
// It is the missing half of ResolveVariant's (bodyAddress, wireVariantID)
// lookup: the in-memory variantIndex above locates the CANDIDATE body (the
// store itself has no reverse index — see variantIndex's doc), and this
// then calls ResolveVariant itself — the SAME narrow, validated read that
// backs the wire RPC — to prove admission, rather than trusting the index
// alone. The variant is used HERE, at admission, and not persisted: a
// caller that needs the exact bytes again later re-derives them from the
// returned body address's variant set (ListVariants / ResolveVariant), the
// same as any other evidence consumer.
//
// A malformed id is ErrInvalidArgument; a well-formed id this node never
// admitted is ErrNotFound.
func (s *Service) ResolveVariantBody(ctx context.Context, wireVariantID string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !vc.IsWireVariantID(wireVariantID) {
		return "", fmt.Errorf("%w: %q is not a wire variant id", ErrInvalidArgument, wireVariantID)
	}
	bodyAddress, ok, err := s.variantIdx.lookup(s.store, wireVariantID)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrNotFound
	}
	// Prove admission with the real validated read rather than trusting the
	// index alone — the index is a lookup aid, not a substitute for the store
	// proving these exact bytes are what it holds.
	if _, err := s.ResolveVariant(ctx, bodyAddress, wireVariantID); err != nil {
		return "", err
	}
	return bodyAddress, nil
}
