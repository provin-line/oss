// Package vcresolver stores VCs submitted by pipeline runtimes and resolves
// previousCredential chains across registry boundaries. This file defines
// the storage contracts; the in-memory PoC implementations and the batch
// resolver land with the service.
package vcresolver

import (
	"errors"

	"github.com/provin-line/oss/packages/vc"
)

// ErrNotFound is returned for misses. Handlers map it with errors.Is.
var ErrNotFound = errors.New("vcresolver: not found")

// Store holds resolved VCs keyed by their content address
// ("sha256:<hex>" over the JCS-canonical body).
type Store interface {
	Put(hash string, cred *vc.PipelinePassCredential) error
	Get(hash string) (*vc.PipelinePassCredential, error)
}

// UnresolvedEntry is one queued chain hole: a previousCredential hash we do
// not hold, plus the upstream endpoint to fetch it from.
type UnresolvedEntry struct {
	Hash             string
	UpstreamEndpoint string
	RetryCount       int
}

// Pool queues unresolved entries for the batch resolver. Ordering is
// newest-first (recent chain holes are the most likely to be resolvable).
type Pool interface {
	Add(e UnresolvedEntry) error
	ListNewest(n int) ([]UnresolvedEntry, error)
	Remove(hash string) error
	IncrementRetry(hash string) error
	Len() int
}
