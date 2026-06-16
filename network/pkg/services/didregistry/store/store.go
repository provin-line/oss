// Package store defines the persistence contracts of the DID registry
// service. Implementations (store/yamlstore) hold no validation logic; they
// build filesystem paths only from safety-checked DID segments.
//
// Private keys are NOT stored here — key custody goes through
// keystore.
package store

import (
	"errors"
	"time"

	"github.com/provin-line/oss/delegation"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/did/dplaax"
)

// ErrNotFound is returned for misses. Handlers map it with errors.Is —
// never by message matching.
var ErrNotFound = errors.New("didregistry: not found")

// ErrExists is returned when a write collides with an existing record (a DID
// is registered/issued twice). Saves create with O_EXCL, so the collision is
// detected at the store boundary; the service decides whether an exact
// re-submission is idempotent. Handlers map it with errors.Is.
var ErrExists = errors.New("didregistry: already exists")

// DIDStatus is the lifecycle status of a stored DID.
type DIDStatus string

const (
	StatusActive  DIDStatus = "active"
	StatusRevoked DIDStatus = "revoked"
)

// DIDSummary is a lightweight listing entry.
type DIDSummary struct {
	DID    string
	Status DIDStatus
}

// LifecycleEvent is one append-only record in a DID's lifecycle log. It is a
// plain persistence shape: the store holds no validation or chaining logic.
// The service builds events (it owns the clock and the hash chain) and the
// store only appends them in order. Fields follow slice-4 D-d4.
type LifecycleEvent struct {
	// EventType is the lifecycle transition. Slice-4 produces "register" /
	// "revoke"; "bind" / "rotate" arrive with later slices. It is a string so
	// new types are additive and no dead enum value ships.
	EventType string
	// DIDDocSnapshot is the canonical-JCS hash ("sha256:<hex>") of the DID
	// Document body at the time of the event — the integrity-protected snapshot.
	DIDDocSnapshot string
	// OutwardSnapshot is the opaque raw bytes of a caller-submitted outward DID
	// document (B7); nil when none was submitted.
	OutwardSnapshot []byte
	// WitnessSource records how the outward binding was witnessed:
	// "self-asserted" now, "registry-resolved" once registry-side resolution
	// (D-d4 part A) lands. Present from the start so that later addition is
	// purely additive and old caller-submitted snapshots stay distinguishable.
	WitnessSource string
	// WitnessedAt is the registry receipt time, injected by the service via its
	// clock seam (not read from the caller).
	WitnessedAt time.Time
	// PrevEventHash chains this event to its predecessor (append-only evidence);
	// computed by the service, empty for the first event in a log.
	PrevEventHash string
}

// DIDStore persists DID Documents and their delegations across the
// owner → pipeline → process hierarchy.
type DIDStore interface {
	SaveOwner(d *dplaax.DID, doc *did.DIDDocument) error
	SavePipeline(d *dplaax.DID, doc *did.DIDDocument, dlg *delegation.DelegationCredential) error
	SaveProcess(d *dplaax.DID, doc *did.DIDDocument, dlg *delegation.DelegationCredential) error

	Resolve(d *dplaax.DID) (*did.DIDDocument, error)
	ResolveDelegation(d *dplaax.DID) (*delegation.DelegationCredential, error)

	UpdateStatus(d *dplaax.DID, status DIDStatus) error
	GetStatus(d *dplaax.DID) (DIDStatus, error)

	ListPipelines(owner *dplaax.DID) ([]DIDSummary, error)
	ListProcesses(pipeline *dplaax.DID) ([]DIDSummary, error)

	// AppendLifecycleEvent records ev on d's append-only log. The store assigns
	// the next sequence position and never rewrites or deletes an existing entry
	// (the append-only guarantee is a store boundary, so the yamlstore→tlog swap
	// is implementation-only). PrevEventHash and WitnessedAt are set by the
	// caller (service); the store does not compute or validate them.
	AppendLifecycleEvent(d *dplaax.DID, ev LifecycleEvent) error
	// ReadLifecycleLog returns d's lifecycle events in append order (oldest
	// first); an empty log for a DID with no events is not an error.
	ReadLifecycleLog(d *dplaax.DID) ([]LifecycleEvent, error)
}
