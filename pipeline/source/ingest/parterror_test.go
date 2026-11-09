package ingest_test

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/internal/pipeexcerpt"
	"github.com/provin-line/oss/pipeline/source/ingest"
)

type nilPointerError struct{ text string }

func (e *nilPointerError) Error() string { return e.text }

// selfPanickingError panics with itself, a value fmt cannot write either.
type selfPanickingError struct{}

func (e selfPanickingError) Error() string { panic(e) }

// A signer's error whose text panics where it is taken without excerpt (an
// Error that panics with a value fmt cannot write; a nil pointer whose Error
// reads through it, which fmt writes as "<nil>") does not make an ingest step
// panic while it writes its result, which names the step within
// pipeexcerpt.TextLimit bytes of UTF-8.
func TestProcess_ASignersErrorWhoseTextPanics(t *testing.T) {
	for _, bad := range []struct {
		name string
		err  error
	}{
		{"nil pointer", (*nilPointerError)(nil)},
		{"panics with itself", selfPanickingError{}},
	} {
		t.Run(bad.name, func(t *testing.T) {
			p, err := ingest.New(ingest.Config{MaxPayloadSize: 1 << 20, Signer: &fakeSourceSigner{returnErr: bad.err}})
			if err != nil {
				t.Fatal(err)
			}
			var r *contract.Result
			done := false
			func() {
				defer func() {
					rec := recover()
					if !done {
						t.Fatalf("Process panicked: %T", rec)
					}
				}()
				r, err = p.Process(context.Background(), []byte(`{"v":1}`))
				done = true
			}()
			if err != nil {
				t.Fatal(err)
			}
			if r.Status != contract.StatusErrored || !strings.Contains(r.Error, "sign") || len(r.Error) > pipeexcerpt.TextLimit || !utf8.ValidString(r.Error) {
				t.Errorf("status %v, Result.Error %.120q (%d bytes)", r.Status, r.Error, len(r.Error))
			}
		})
	}
}
