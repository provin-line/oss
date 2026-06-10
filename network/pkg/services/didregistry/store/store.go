// Package store defines the persistence contracts of the DID registry
// service. Implementations (store/yamlstore) hold no validation logic; they
// build filesystem paths only from safety-checked DID segments.
//
// Private keys are NOT stored here — key custody goes through
// packages/keystore.
package store

import (
	"errors"

	"github.com/provin-line/oss/packages/delegation"
	"github.com/provin-line/oss/packages/did"
)

// ErrNotFound is returned for misses. Handlers map it with errors.Is —
// never by message matching.
var ErrNotFound = errors.New("didregistry: not found")

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

// DIDStore persists DID Documents and their delegations across the
// owner → pipeline → process hierarchy.
type DIDStore interface {
	SaveOwner(d *did.DID, doc *did.DIDDocument) error
	SavePipeline(d *did.DID, doc *did.DIDDocument, dlg *delegation.DelegationCredential) error
	SaveProcess(d *did.DID, doc *did.DIDDocument, dlg *delegation.DelegationCredential) error

	Resolve(d *did.DID) (*did.DIDDocument, error)
	ResolveDelegation(d *did.DID) (*delegation.DelegationCredential, error)

	UpdateStatus(d *did.DID, status DIDStatus) error
	GetStatus(d *did.DID) (DIDStatus, error)

	ListPipelines(owner *did.DID) ([]DIDSummary, error)
	ListProcesses(pipeline *did.DID) ([]DIDSummary, error)
}
