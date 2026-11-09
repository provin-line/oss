package ingest_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/internal/pipeexcerpt"
	"github.com/provin-line/oss/pipeline/source/ingest"
)

// An ingest step's errored Result names its error within
// pipeexcerpt.TextLimit bytes of UTF-8, however long: a signer's error.
func TestProcess_ErroredResultWithinTheLimit(t *testing.T) {
	p, err := ingest.New(ingest.Config{MaxPayloadSize: 1 << 20, Signer: &fakeSourceSigner{returnErr: errors.New(strings.Repeat("ab\n\xff", 64<<10))}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Process(context.Background(), []byte(`{"v":1}`))
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
