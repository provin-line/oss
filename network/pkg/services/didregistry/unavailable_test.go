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

// The sentinels are constants of didregistry.Error: these lines stop compiling
// if one is not.
const (
	_ didregistry.Error = didregistry.ErrInvalidArgument
	_ didregistry.Error = didregistry.ErrUnauthorized
	_ didregistry.Error = didregistry.ErrUnavailable
)

func TestSentinelTexts(t *testing.T) {
	for err, want := range map[error]string{
		didregistry.ErrInvalidArgument: "didregistry: invalid argument",
		didregistry.ErrUnauthorized:    "didregistry: unauthorized",
		didregistry.ErrUnavailable:     "didregistry: unavailable",
	} {
		if err.Error() != want {
			t.Errorf("%q, want %q", err.Error(), want)
		}
	}
}

// ownerUnreadable is a store that answers for the owner's document with err,
// with doc, or with neither when nothing is set, once unreadable is set, and
// otherwise as the embedded store does.
type ownerUnreadable struct {
	store.DIDStore
	unreadable bool
	err        error
	doc        *did.DIDDocument
}

func (s *ownerUnreadable) Resolve(d *dplaax.DID) (*did.DIDDocument, error) {
	if s.unreadable && d.String() == ownerDID {
		return s.doc, s.err
	}
	return s.DIDStore.Resolve(d)
}

// A delegation whose owner's document the registry cannot read now is
// ErrUnavailable, not ErrUnauthorized: the registry could not decide it, and
// a later request may succeed.
func TestIssue_OwnerDocumentUnreadableNowIsUnavailable(t *testing.T) {
	imposter := did.New(did.DocumentFields{
		Context:    did.IssuedDocumentContexts(),
		ID:         "did:dplaax:poc.dplaax.dev:org:imposter",
		Controller: "did:dplaax:poc.dplaax.dev:org:imposter",
	})
	for name, unreadable := range map[string]func(*ownerUnreadable){
		"a store error":                   func(s *ownerUnreadable) { s.err = errors.New("store busy") },
		"another DID's document":          func(s *ownerUnreadable) { s.doc = imposter },
		"neither a document nor an error": func(*ownerUnreadable) {},
	} {
		for kind, target := range map[string]string{"pipeline": pipelineDID, "process": processDID} {
			st := &ownerUnreadable{DIDStore: yamlstore.New(t.TempDir())}
			svc, signer, signPub, _ := newServiceOn(t, st)
			registerOwner(t, svc, signer, signPub)
			st.unreadable = true
			unreadable(st)
			issue := svc.IssuePipeline
			if kind == "process" {
				issue = svc.IssueProcess
			}
			_, _, err := issue(context.Background(), target, mustDelegate(t, signer, target), nil)
			if !errors.Is(err, didregistry.ErrUnavailable) || errors.Is(err, didregistry.ErrUnauthorized) {
				t.Errorf("%s, %s: %v, want ErrUnavailable and not ErrUnauthorized", name, kind, err)
			}
		}
	}
}

// A delegation the registry refuses for good stays ErrUnauthorized, and is not
// ErrUnavailable.
func TestIssue_DefiniteRefusalIsNotUnavailable(t *testing.T) {
	svc, signer, signPub := newService(t)
	unregistered, _, _ := newService(t)
	registerOwner(t, svc, signer, signPub)
	forged := mustDelegate(t, signer, pipelineDID)
	forged.Proof.ProofValue = "z" + forged.Proof.ProofValue[2:] + "1"
	for name, c := range map[string]struct {
		svc *didregistry.Service
		dlg *delegation.DelegationCredential
	}{
		"an owner the registry does not have": {unregistered, mustDelegate(t, signer, pipelineDID)},
		"a delegation for another pipeline":   {svc, mustDelegate(t, signer, pipelineDID+"x")},
		"a forged signature":                  {svc, forged},
	} {
		_, _, err := c.svc.IssuePipeline(context.Background(), pipelineDID, c.dlg, nil)
		if !errors.Is(err, didregistry.ErrUnauthorized) || errors.Is(err, didregistry.ErrUnavailable) {
			t.Errorf("%s: %v, want ErrUnauthorized and not ErrUnavailable", name, err)
		}
	}
}
