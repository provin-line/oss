// Package inputcapture records the immutable identities of external inputs a
// verifier actually reads during one appraisal. Wrappers are context-scoped so
// concurrent evaluations sharing one resolver cannot mix their snapshots.
package inputcapture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/provin-line/oss/canon/jcs"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/resolver"
	"github.com/provin-line/oss/vc"
)

var (
	ErrNoSnapshots      = errors.New("inputcapture: appraisal read no external snapshots")
	ErrSnapshotConflict = errors.New("inputcapture: one input name resolved to different snapshots")
)

type captureKey struct{}

// Session is one appraisal's isolated capture ledger.
type Session struct {
	mu        sync.Mutex
	digests   map[string]string
	conflicts []string
}

// Recorder starts context-bound sessions. It is stateless and concurrency-safe.
type Recorder struct{}

// Start attaches a fresh Session to ctx.
func (Recorder) Start(ctx context.Context) (context.Context, *Session) {
	s := &Session{digests: make(map[string]string)}
	return context.WithValue(ctx, captureKey{}, s), s
}

// Digests returns an isolated copy, rejecting empty or internally inconsistent
// captures so an accepted view cannot silently omit its resolver inputs.
func (s *Session) Digests() (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.conflicts) > 0 {
		return nil, fmt.Errorf("%w: %v", ErrSnapshotConflict, s.conflicts)
	}
	if len(s.digests) == 0 {
		return nil, ErrNoSnapshots
	}
	out := make(map[string]string, len(s.digests))
	for key, value := range s.digests {
		out[key] = value
	}
	return out, nil
}

func record(ctx context.Context, name, digest string) {
	s, ok := ctx.Value(captureKey{}).(*Session)
	if !ok || s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if prior, exists := s.digests[name]; exists && prior != digest {
		s.conflicts = append(s.conflicts, name)
		return
	}
	s.digests[name] = digest
}

// DIDResolver records the canonical hash of each successfully resolved DID
// document, then returns the original object unchanged.
type DIDResolver struct {
	Next resolver.Resolver
}

func (r DIDResolver) Resolve(ctx context.Context, didString string) (*did.DIDDocument, error) {
	doc, err := r.Next.Resolve(ctx, didString)
	if err != nil || doc == nil {
		return doc, err
	}
	digest, err := doc.Hash()
	if err != nil {
		return nil, fmt.Errorf("inputcapture: hash DID document %s: %w", didString, err)
	}
	record(ctx, "did:"+didString, digest)
	return doc, nil
}

// SchemaResolver records both the returned schema bytes and the returned
// format because either field changes the verifier's result.
type SchemaResolver struct {
	Next vc.SchemaResolver
}

func (r SchemaResolver) ResolveSchema(ctx context.Context, ref vc.SchemaRef) (*vc.ResolvedSchema, error) {
	resolved, err := r.Next.ResolveSchema(ctx, ref)
	if err != nil || resolved == nil {
		return resolved, err
	}
	bodySum := sha256.Sum256(resolved.Body)
	projection := map[string]any{
		"bodyDigest": "sha256:" + hex.EncodeToString(bodySum[:]),
		"format":     resolved.Format,
	}
	digest, err := jcs.HashRFC8785(projection)
	if err != nil {
		return nil, fmt.Errorf("inputcapture: hash schema snapshot %s: %w", ref.ID, err)
	}
	record(ctx, "schema:"+ref.ID, digest)
	return resolved, nil
}
