package chained_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/provin-line/oss/pipeline/chained"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/internal/pipeexcerpt"
)

// A chained step's errored Result names its error within
// pipeexcerpt.TextLimit bytes of UTF-8, however long: a verifier's error.
func TestProcess_ErroredResultWithinTheLimit(t *testing.T) {
	payload := []byte(`{"v":1}`)
	cfg := baseAdjacentConfig(&fakeVerifier{err: errors.New(strings.Repeat("ab\n\xff", 64<<10))}, &fakeStore{}, &fakeSigner{})
	p, err := chained.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Process(context.Background(), encodeEnvelope(t, newIngressCred(t, payload), payload))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != contract.StatusErrored {
		t.Fatalf("status %v, want errored", r.Status)
	}
	if len(r.Error) > pipeexcerpt.TextLimit || !utf8.ValidString(r.Error) {
		t.Errorf("Result.Error of %d bytes (UTF-8: %v)", len(r.Error), utf8.ValidString(r.Error))
	}
}
