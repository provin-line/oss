package chained_test

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/provin-line/oss/pipeline/chained"
	"github.com/provin-line/oss/pipeline/chained/filter"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/internal/pipeexcerpt"
)

type nilPointerError struct{ text string }

func (e *nilPointerError) Error() string { return e.text }

// selfPanickingError panics with itself, a value fmt cannot write either.
type selfPanickingError struct{}

func (e selfPanickingError) Error() string { panic(e) }

// failingCodec refuses every envelope with err.
type failingCodec struct{ err error }

func (c failingCodec) MarshalEnvelope(*contract.Envelope) ([]byte, error) { return nil, c.err }
func (c failingCodec) UnmarshalEnvelope([]byte) (*contract.Envelope, error) {
	return nil, c.err
}

// An error a part returns whose text panics where it is taken without
// excerpt (an Error that panics with a value fmt cannot write; a nil pointer
// whose Error reads through it, which fmt writes as "<nil>") does not make a
// chained step panic while it writes its result: on each path below the
// errored Result names the step, within pipeexcerpt.TextLimit bytes.
func TestProcess_APartsErrorWhoseTextPanics(t *testing.T) {
	payload := []byte(`{"v":1}`)
	for _, bad := range []struct {
		name string
		err  error
	}{
		{"nil pointer", (*nilPointerError)(nil)},
		{"panics with itself", selfPanickingError{}},
	} {
		for _, c := range []struct {
			name, keeps string
			set         func(*chained.Config, error)
			byRef       bool
		}{
			{"codec", "decode envelope", func(cfg *chained.Config, err error) { cfg.Codec = failingCodec{err} }, false},
			{"verifier", "verification error", func(cfg *chained.Config, err error) { cfg.Verifier = &fakeVerifier{err: err} }, false},
			{"store", "store ingress VC", func(cfg *chained.Config, err error) { cfg.Store = &fakeStore{returnErr: err} }, false},
			{"filter", "filter[0] step failure", func(cfg *chained.Config, err error) { cfg.Filters = []filter.Filter{&fakeFilter{err: err}} }, false},
			{"converter", "converter", func(cfg *chained.Config, err error) { cfg.Converter = &fakeConverter{err: err} }, false},
			{"signer", "sign", func(cfg *chained.Config, err error) { cfg.Signer = &fakeSigner{returnErr: err} }, false},
			{"input validator", "input schema validation", func(cfg *chained.Config, err error) {
				cfg.InputValidator, cfg.InputSchemaRef = &fakeValidator{returnErr: err}, makeSchemaRef()
			}, false},
			{"output validator", "output schema validation", func(cfg *chained.Config, err error) {
				cfg.OutputValidator, cfg.OutputSchemaRef = &fakeValidator{returnErr: err}, makeSchemaRef()
			}, false},
			{"payload resolver", "fetch by-reference payload", func(cfg *chained.Config, err error) {
				cfg.PayloadDelivery, cfg.PayloadResolver = contract.DeliveryByReference, &fakePayloadResolver{err: err}
			}, true},
		} {
			t.Run(c.name+", "+bad.name, func(t *testing.T) {
				cfg := baseAdjacentConfig(&fakeVerifier{result: verifiedResult()}, &fakeStore{}, &fakeSigner{})
				c.set(&cfg, bad.err)
				p, err := chained.New(cfg)
				if err != nil {
					t.Fatal(err)
				}
				wire := encodeEnvelope(t, newIngressCred(t, payload), payload)
				if c.byRef {
					wire = encodeEnvelopeByRef(t, newIngressCred(t, payload))
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
					r, err = p.Process(context.Background(), wire)
					done = true
				}()
				if err != nil {
					t.Fatal(err)
				}
				if r.Status != contract.StatusErrored {
					t.Fatalf("status %v, want errored", r.Status)
				}
				if len(r.Error) > pipeexcerpt.TextLimit || !utf8.ValidString(r.Error) || !strings.Contains(r.Error, c.keeps) {
					t.Errorf("Result.Error %.120q (%d bytes), want it to name %q", r.Error, len(r.Error), c.keeps)
				}
			})
		}
	}
}
