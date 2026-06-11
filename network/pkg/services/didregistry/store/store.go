// Package store defines the persistence contracts of the DID registry
// service. Implementations (store/yamlstore) hold no validation logic; they
// build filesystem paths only from safety-checked DID segments.
//
// Private keys are NOT stored here — key custody goes through
// keystore.
package store

import (
	"errors"

	"github.com/provin-line/oss/delegation"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/did/dplaax"
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
	SaveOwner(d *dplaax.DID, doc *did.DIDDocument) error
	SavePipeline(d *dplaax.DID, doc *did.DIDDocument, dlg *delegation.DelegationCredential) error
	SaveProcess(d *dplaax.DID, doc *did.DIDDocument, dlg *delegation.DelegationCredential) error

	Resolve(d *dplaax.DID) (*did.DIDDocument, error)
	ResolveDelegation(d *dplaax.DID) (*delegation.DelegationCredential, error)

	UpdateStatus(d *dplaax.DID, status DIDStatus) error
	GetStatus(d *dplaax.DID) (DIDStatus, error)

	ListPipelines(owner *dplaax.DID) ([]DIDSummary, error)
	ListProcesses(pipeline *dplaax.DID) ([]DIDSummary, error)
}
