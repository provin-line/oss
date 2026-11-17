package didregistry_test

import (
	"context"
	"errors"
	"testing"

	"github.com/provin-line/oss/delegation"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/network/pkg/services/didregistry"
	"github.com/provin-line/oss/network/pkg/services/didregistry/store"
	"github.com/provin-line/oss/network/pkg/services/didregistry/store/yamlstore"
)

// unreadable is a store whose Resolve and ResolveDelegation fail with an
// error that is not a miss.
type unreadable struct{ store.DIDStore }

var errUnreadable = errors.New("store unreadable")

func (unreadable) Resolve(*dplaax.DID) (*did.DIDDocument, error) { return nil, errUnreadable }
func (unreadable) ResolveDelegation(*dplaax.DID) (*delegation.DelegationCredential, error) {
	return nil, errUnreadable
}

// readCases are the requests ResolveDID and ResolveDelegation are held to:
// each answers with the error it names, never with neither.
func readCases(t *testing.T) (*didregistry.Service, *didregistry.Service, map[string]struct {
	svc  *didregistry.Service
	ctx  context.Context
	did  string
	want error
}) {
	t.Helper()
	svc, signer, signPub := newService(t)
	registerOwner(t, svc, signer, signPub)
	if _, _, err := svc.IssuePipeline(context.Background(), pipelineDID, mustDelegate(t, signer, pipelineDID), nil); err != nil {
		t.Fatalf("IssuePipeline: %v", err)
	}
	broken, _, _, _ := newServiceOn(t, unreadable{yamlstore.New(t.TempDir())})
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	return svc, broken, map[string]struct {
		svc  *didregistry.Service
		ctx  context.Context
		did  string
		want error
	}{
		"a DID it does not hold":    {svc, context.Background(), processDID, store.ErrNotFound},
		"a DID that does not parse": {svc, context.Background(), "did:dplaax:", didregistry.ErrInvalidArgument},
		"a DID of another registry": {svc, context.Background(), "did:dplaax:other.example:org:acme", didregistry.ErrUnauthorized},
		"an ended context":          {svc, ended, pipelineDID, context.Canceled},
		"a store that fails":        {broken, context.Background(), pipelineDID, errUnreadable},
	}
}

// ResolveDID answers with a document or an error, never with neither.
func TestResolveDID_ReturnsADocumentOrAnError(t *testing.T) {
	svc, _, cases := readCases(t)
	if doc, err := svc.ResolveDID(context.Background(), pipelineDID); doc == nil || err != nil {
		t.Errorf("a DID it holds: %v, %v, want its document", doc, err)
	}
	for name, c := range cases {
		doc, err := c.svc.ResolveDID(c.ctx, c.did)
		if doc != nil || !errors.Is(err, c.want) {
			t.Errorf("%s: %v, %v, want no document and %v", name, doc, err, c.want)
		}
	}
}

// ResolveDelegation answers with a delegation or an error, never with neither.
func TestResolveDelegation_ReturnsADelegationOrAnError(t *testing.T) {
	svc, _, cases := readCases(t)
	if dlg, err := svc.ResolveDelegation(context.Background(), pipelineDID); dlg == nil || err != nil {
		t.Errorf("a DID it holds: %v, %v, want its delegation", dlg, err)
	}
	for name, c := range cases {
		dlg, err := c.svc.ResolveDelegation(c.ctx, c.did)
		if dlg != nil || !errors.Is(err, c.want) {
			t.Errorf("%s: %v, %v, want no delegation and %v", name, dlg, err, c.want)
		}
	}
}
