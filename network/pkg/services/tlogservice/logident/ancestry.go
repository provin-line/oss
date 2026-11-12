package logident

import (
	"context"
	"errors"
	"fmt"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/internal/netexcerpt"
)

// ErrInvalidProcessDID is returned by AncestorPipeline when processDID does
// not parse as a valid, semantically-checked process DID, or when the
// registry's own record does not resolve to a valid pipeline ancestor.
// Fail-closed: a bad shape is never treated as "no ancestor".
var ErrInvalidProcessDID = errors.New("logident: invalid process DID")

// PipelineAncestry answers "which pipeline DID issued this process DID" —
// the check an emission log's writer binding needs (the checkpoint
// signer is a process DID, but the log id names the pipeline; verifying the
// signer belongs to that pipeline requires walking from process to
// pipeline). Defined here as an interface, consumed by the writer-binding
// predicate that composes Kind + OwnerDID + SignerBase + AncestorPipeline.
type PipelineAncestry interface {
	// AncestorPipeline returns the pipeline DID that issued processDID.
	// Fail-closed: an unparseable/wrong-kind processDID, an unresolvable
	// one, or a resolved record with no valid pipeline ancestor is always
	// an error, never an empty success.
	AncestorPipeline(ctx context.Context, processDID string) (string, error)
}

// DIDResolver is the read view DIDRegistryAncestry needs. *didregistry.Service
// satisfies it (see didregistry/handler/resolution.go's identically-shaped
// Resolver for the established precedent of declaring this narrow interface
// locally rather than importing the concrete service type).
//
// ResolveDID returns a non-nil document or a non-nil error, never both nil,
// as didregistry.Service's ResolveDID does.
type DIDResolver interface {
	ResolveDID(ctx context.Context, didStr string) (*did.DIDDocument, error)
}

// DIDRegistryAncestry implements PipelineAncestry over the DID registry's
// own issuance records — no new store index. Verified fact
// (didregistry.go's issue/assembleDoc, confirmed by
// TestFullLifecycle/procDoc.Controller() == pipelineDID): a Process
// document's "controller" field is set to its structural parent, the
// Pipeline DID that issued it (assembleDoc: parent = target.PipelineDID()
// for kindProcess). Resolving the process DID and reading Controller() is
// therefore the narrowest existing read that answers the ancestry
// question — the registry issues process DIDs under pipelines and records
// the relationship in the document it already serves.
type DIDRegistryAncestry struct {
	resolver DIDResolver
}

var _ PipelineAncestry = (*DIDRegistryAncestry)(nil)

// NewDIDRegistryAncestry returns a DIDRegistryAncestry reading through
// resolver (typically a *didregistry.Service).
func NewDIDRegistryAncestry(resolver DIDResolver) *DIDRegistryAncestry {
	return &DIDRegistryAncestry{resolver: resolver}
}

// AncestorPipeline resolves processDID's DID Document and returns its
// controller, validated as a pipeline DID.
func (a *DIDRegistryAncestry) AncestorPipeline(ctx context.Context, processDID string) (string, error) {
	if _, err := parseProcessDID(processDID); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidProcessDID, err)
	}
	doc, err := a.resolver.ResolveDID(ctx, processDID)
	if err != nil {
		return "", fmt.Errorf("logident: resolve process DID %q: %w", processDID, err)
	}
	controller := doc.Controller()
	if _, err := parsePipelineDID(controller); err != nil {
		return "", fmt.Errorf("%w: process %s controller %s: %v", ErrInvalidProcessDID, netexcerpt.ValueText(processDID), netexcerpt.ValueText(controller), err)
	}
	return controller, nil
}
