package sink_test

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/provin-line/oss/appraisal"
	"github.com/provin-line/oss/decisionrecord"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/sink"
	"github.com/provin-line/oss/vc"
)

type nilPointerError struct{ text string }

func (e *nilPointerError) Error() string { return e.text }

// selfPanickingError panics with itself, a value fmt cannot write either.
type selfPanickingError struct{}

func (e selfPanickingError) Error() string { panic(e) }

// textPanics are errors whose text panics when it is taken without excerpt:
// a nil pointer whose Error reads through it, where Error is called directly
// (fmt writes it as "<nil>"), and one whose Error panics with a value fmt
// cannot write, wherever its text is taken.
var textPanics = []struct {
	name string
	err  error
}{
	{"nil pointer", (*nilPointerError)(nil)},
	{"panics with itself", selfPanickingError{}},
}

// failingCodec refuses every envelope with err.
type failingCodec struct{ err error }

func (c failingCodec) MarshalEnvelope(*contract.Envelope) ([]byte, error) { return nil, c.err }
func (c failingCodec) UnmarshalEnvelope([]byte) (*contract.Envelope, error) {
	return nil, c.err
}

// failingRecorder refuses every decision record with err.
type failingRecorder struct{ err error }

func (r failingRecorder) Record(context.Context, decisionrecord.Record) error { return r.err }

// An error a part returns whose text panics does not make the sink panic
// while it writes its result, its reject record or its decision's reason: on
// each path below the Result names the step, within pipeexcerpt.TextLimit
// bytes.
func TestProcess_APartsErrorWhoseTextPanics(t *testing.T) {
	good := []byte(`{"v":1}`)
	plain := func(set func(*sink.Config, error)) func(*testing.T, *vc.PipelinePassCredential, error) sink.Config {
		return func(_ *testing.T, _ *vc.PipelinePassCredential, err error) sink.Config {
			cfg := baseConfig(&fakeVerifier{result: verified()}, &fakeStore{}, &fakeWriter{})
			set(&cfg, err)
			return cfg
		}
	}
	for _, bad := range textPanics {
		for _, c := range []struct {
			name, keeps string
			config      func(*testing.T, *vc.PipelinePassCredential, error) sink.Config
		}{
			{"codec", "decode envelope", plain(func(cfg *sink.Config, err error) { cfg.Codec = failingCodec{err} })},
			{"appraiser", "exact-view appraisal failed", func(_ *testing.T, _ *vc.PipelinePassCredential, err error) sink.Config {
				return agentConfig(&fakeAppraiser{err: err}, &fakeStore{}, &fakeWriter{}, &fakeRecorder{})
			}},
			{"decision recorder", "record delivery decision", func(t *testing.T, cred *vc.PipelinePassCredential, err error) sink.Config {
				view := appraisedView(t, cred, appraisal.TruthVerified, appraisal.DecisionAccept)
				return agentConfig(&fakeAppraiser{view: view, result: verified()}, &fakeStore{}, &fakeWriter{}, failingRecorder{err})
			}},
			{"store", "store ingress VC", plain(func(cfg *sink.Config, err error) { cfg.Store = &fakeStore{returnErr: err} })},
			{"writer", "external write", plain(func(cfg *sink.Config, err error) { cfg.Writer = &fakeWriter{returnErr: err} })},
			{"receipt issuer", "issue sink receipt", plain(func(cfg *sink.Config, err error) { cfg.Receipts = &fakeReceiptIssuer{err: err} })},
			{"payload resolver", "fetch by-reference payload", plain(func(cfg *sink.Config, err error) {
				cfg.PayloadDelivery, cfg.PayloadResolver = contract.DeliveryByReference, &fakePayloadResolver{err: err}
			})},
		} {
			t.Run(c.name+", "+bad.name, func(t *testing.T) {
				cred := boundCred(t, good)
				cfg := c.config(t, cred, bad.err)
				cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
				p, err := sink.New(cfg)
				if err != nil {
					t.Fatal(err)
				}
				wire := encode(t, cred, good)
				if cfg.PayloadDelivery == contract.DeliveryByReference {
					wire = encode(t, cred, nil)
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
				requireWithin(t, "Result.Error", r.Error)
				if !strings.Contains(r.Error, c.keeps) {
					t.Errorf("Result.Error %.120q does not name %q", r.Error, c.keeps)
				}
			})
		}
	}
}
