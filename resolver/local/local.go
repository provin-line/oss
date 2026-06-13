// Package local is the in-memory resolver.Resolver for tests and fixtures: a
// DID → DID Document map. It is the PoC stand-in for the registry-backed
// resolvers (grpc / multi); deployments that need durability or a real
// registry use those instead.
package local

import (
	"context"
	"fmt"
	"sync"

	"github.com/provin-line/oss/did"
)

// Resolver is an in-memory DID resolver. Safe for concurrent use.
type Resolver struct {
	mu   sync.RWMutex
	docs map[string]*did.DIDDocument
}

// New returns an empty Resolver.
func New() *Resolver {
	return &Resolver{docs: map[string]*did.DIDDocument{}}
}

// Add registers doc under its ID, overwriting any existing entry.
func (r *Resolver) Add(doc *did.DIDDocument) {
	r.mu.Lock()
	r.docs[doc.ID] = doc
	r.mu.Unlock()
}

// Resolve returns the document registered for didStr, or an error if none is.
// The returned document's ID equals didStr by construction (Add keys by ID),
// mirroring the registry-substitution defense the grpc resolver enforces.
func (r *Resolver) Resolve(_ context.Context, didStr string) (*did.DIDDocument, error) {
	r.mu.RLock()
	doc, ok := r.docs[didStr]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("local resolver: no document for %q", didStr)
	}
	return doc, nil
}
