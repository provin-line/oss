package bundle

import (
	"context"
	"errors"
	"testing"

	"github.com/provin-line/oss/did"
)

const contractDID = "did:dplaax:poc.dplaax.dev:org:acme"

// archiveResolver answers with a document or an error, never with neither
// (resolver.Resolver).
func TestArchiveResolver_ReturnsADocumentOrAnError(t *testing.T) {
	a := &archiveResolver{docs: map[string]*did.DIDDocument{contractDID: did.New(did.DocumentFields{ID: contractDID})}}
	for _, d := range []string{contractDID, contractDID + "x", ""} {
		if doc, err := a.Resolve(context.Background(), d); doc == nil && err == nil {
			t.Errorf("Resolve(%q): neither a document nor an error", d)
		}
	}
}

// documents is a DocumentSource that answers from a map, and with err for a
// DID it does not hold.
type documents struct {
	raw map[string][]byte
	err error
}

func (s documents) FetchDocument(_ context.Context, d string) ([]byte, error) {
	if raw, ok := s.raw[d]; ok {
		return raw, nil
	}
	return nil, s.err
}

// recordingResolver answers with a document or an error, never with neither
// (resolver.Resolver), whatever its source answers, and also from what it has
// recorded.
func TestRecordingResolver_ReturnsADocumentOrAnError(t *testing.T) {
	doc, err := did.New(did.DocumentFields{ID: contractDID}).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	other, err := did.New(did.DocumentFields{ID: contractDID + "x"}).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	r := newRecordingResolver(documents{
		raw: map[string][]byte{
			contractDID:                  doc,
			contractDID + ":pipeline:p1": other,
			contractDID + ":pipeline:p2": []byte("{"),
			contractDID + ":pipeline:p4": nil,
		},
		err: errors.New("source unavailable"),
	})
	for _, d := range []string{
		contractDID,                  // fetched
		contractDID,                  // recorded
		contractDID + ":pipeline:p1", // another DID's document
		contractDID + ":pipeline:p2", // no JSON
		contractDID + ":pipeline:p3", // the source fails
		contractDID + ":pipeline:p4", // the source answers with neither
		"did:dplaax:",                // does not parse
	} {
		if got, err := r.Resolve(context.Background(), d); got == nil && err == nil {
			t.Errorf("Resolve(%q): neither a document nor an error", d)
		}
	}
}
