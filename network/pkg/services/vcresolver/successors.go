package vcresolver

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// indexBuildPage is the ListHashes page size the lazy index build scans with.
const indexBuildPage = 512

// successorIndex is the in-memory previousCredential forward index behind
// ListSuccessors: prev content address → the set of held successors. It is
// built lazily on first use by scanning the store (boot cost zero; the
// first ListSuccessors call pays O(store)) and maintained by StoreVC's put
// path afterwards. In-memory only — a restart rebuilds from the store; an
// implementation may later persist it without touching any contract.
//
// Concurrency contract: one mutex guards build state and map. The initial
// build holds the lock for the whole scan; StoreVC's add blocks on it and
// applies after — set semantics make a doubly-observed edge (seen by the
// scan AND applied by the pending add) harmless. Before the first build,
// add is a no-op: the store itself is the source of truth the build reads.
type successorIndex struct {
	mu    sync.Mutex
	built bool
	m     map[string]map[string]struct{}
}

// add records the edge prev→succ if the index is materialized.
func (ix *successorIndex) add(prev, succ string) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if !ix.built {
		return
	}
	ix.insert(prev, succ)
}

func (ix *successorIndex) insert(prev, succ string) {
	set, ok := ix.m[prev]
	if !ok {
		set = make(map[string]struct{})
		ix.m[prev] = set
	}
	set[succ] = struct{}{}
}

// page returns up to limit successors of prev in lexicographic order,
// strictly after fromExclusive, and whether more remain past the page.
// It builds the index from store on first use.
func (ix *successorIndex) page(store *VariantStore, prev, fromExclusive string, limit int) (successors []string, more bool, err error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if !ix.built {
		if err := ix.build(store); err != nil {
			return nil, false, err
		}
	}
	all := make([]string, 0, len(ix.m[prev]))
	for h := range ix.m[prev] {
		if h > fromExclusive {
			all = append(all, h)
		}
	}
	sort.Strings(all)
	if len(all) > limit {
		return all[:limit], true, nil
	}
	return all, false, nil
}

// build scans the whole store: every held credential's raw previousCredential
// becomes an edge. Link extraction uses the strict raw accessor — a malformed
// link must fail the build loudly, never be read as "origin" — and a damaged
// entry is a hard error: silently skipping it could answer a recall
// investigation with a false "no descendants" (the one caller class for whom
// a silently incomplete index is worse than an error).
func (ix *successorIndex) build(store *VariantStore) error {
	m := make(map[string]map[string]struct{})
	cursor := ""
	for {
		hashes, err := store.ListHashes(cursor, indexBuildPage)
		if err != nil {
			return fmt.Errorf("vcresolver: successor index build: %w", err)
		}
		if len(hashes) == 0 {
			break
		}
		for _, h := range hashes {
			cred, err := store.Get(h)
			if err != nil {
				return fmt.Errorf("vcresolver: successor index build: credential %s: %w", h, err)
			}
			prev, hasPrev, err := rawPreviousCredential(cred.Body())
			if err != nil {
				return fmt.Errorf("vcresolver: successor index build: credential %s: %w", h, err)
			}
			if hasPrev {
				if !isContentAddress(prev) {
					// A string-but-malformed link is store damage: indexing
					// it under an invalid key would make the damaged
					// credential INVISIBLE (ListSuccessors rejects malformed
					// query hashes), letting a recall over a damaged store
					// answer with a clean empty page. Fail the build loudly.
					return fmt.Errorf("vcresolver: successor index build: credential %s: previousCredential %q is not a sha256:<hex> content address", h, prev)
				}
				if set, ok := m[prev]; ok {
					set[h] = struct{}{}
				} else {
					m[prev] = map[string]struct{}{h: {}}
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

// ListSuccessors returns up to limit content addresses of credentials HELD
// BY THIS NODE whose previousCredential is hash, in lexicographic order
// strictly after fromExclusive, plus whether more remain. An unknown or
// childless hash is an empty page, never an error — "no known successors"
// is a normal answer scoped to this node's store. Linear edges only: an
// aggregate references its sources via its receipt, which is the audit
// service's surface.
func (s *Service) ListSuccessors(ctx context.Context, hash, fromExclusive string, limit int) ([]string, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if !isContentAddress(hash) {
		return nil, false, fmt.Errorf("%w: hash %q is not a sha256:<hex> content address", ErrInvalidArgument, hash)
	}
	if limit <= 0 {
		return nil, false, fmt.Errorf("%w: limit %d is not positive", ErrInvalidArgument, limit)
	}
	return s.index.page(s.store, hash, fromExclusive, limit)
}
