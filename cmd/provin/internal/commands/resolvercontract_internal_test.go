package commands

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/provin-line/oss/did"
)

// answer is an httpDoer that answers every request with status and body, or
// fails with err.
type answer struct {
	status int
	body   []byte
	err    error
}

func (a answer) Do(*http.Request) (*http.Response, error) {
	if a.err != nil {
		return nil, a.err
	}
	return &http.Response{StatusCode: a.status, Body: io.NopCloser(bytes.NewReader(a.body))}, nil
}

// registryDocResolver answers with a document or an error, never with
// neither (resolver.Resolver), whatever the registry answers.
func TestRegistryDocResolver_ReturnsADocumentOrAnError(t *testing.T) {
	const owner = "did:dplaax:poc.dplaax.dev:org:acme"
	doc, err := did.New(did.DocumentFields{ID: owner}).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	other, err := did.New(did.DocumentFields{ID: owner + "x"}).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		answer answer
		did    string
	}{
		"a document":                {answer: answer{status: http.StatusOK, body: doc}},
		"not found":                 {answer: answer{status: http.StatusNotFound}},
		"a server error":            {answer: answer{status: http.StatusInternalServerError}},
		"a body that is no JSON":    {answer: answer{status: http.StatusOK, body: []byte("{")}},
		"an empty body":             {answer: answer{status: http.StatusOK}},
		"an oversized body":         {answer: answer{status: http.StatusOK, body: []byte(strings.Repeat(" ", maxRegistryDocSize+1))}},
		"another DID's document":    {answer: answer{status: http.StatusOK, body: other}},
		"a failed request":          {answer: answer{err: errors.New("connection refused")}},
		"a DID that does not parse": {answer: answer{status: http.StatusOK, body: doc}, did: "did:dplaax:"},
	} {
		d := c.did
		if d == "" {
			d = owner
		}
		r := &registryDocResolver{httpClient: c.answer, registry: "https://poc.dplaax.dev"}
		if got, err := r.Resolve(context.Background(), d); got == nil && err == nil {
			t.Errorf("%s: neither a document nor an error", name)
		}
	}
}
