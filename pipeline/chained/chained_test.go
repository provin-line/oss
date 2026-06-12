// Package chained_test tests the Chained Process event processor.
//
// Test strategy: real codec (envelopecodec), real filter/converter (jsonata)
// where cheap. Recording fakes for Verifier, ChainVerifier, Signer, Store,
// Validators, and Observers — they record args so call-order and predecessor
// identity can be asserted.
package chained_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	pipelinev1 "github.com/provin-line/oss/gen/go/dplaax/pipeline/v1"
	"github.com/provin-line/oss/pipeline/chained"
	converterjsonata "github.com/provin-line/oss/pipeline/chained/converter/jsonata"
	"github.com/provin-line/oss/pipeline/chained/filter"
	filterjsonata "github.com/provin-line/oss/pipeline/chained/filter/jsonata"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	"github.com/provin-line/oss/vc"
	"google.golang.org/protobuf/proto"
)

// compile-time: *Processor must implement contract.EventProcessor.
var _ contract.EventProcessor = (*chained.Processor)(nil)

// ---------------------------------------------------------------------------
// Recording fakes
// ---------------------------------------------------------------------------

type fakeVerifier struct {
	calls  []*vc.PipelinePassCredential
	result *vc.VerifyResult
	err    error
}

func (f *fakeVerifier) Verify(_ context.Context, cred *vc.PipelinePassCredential) (*vc.VerifyResult, error) {
	f.calls = append(f.calls, cred)
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

type fakeChainVerifier struct {
	calls  []*vc.PipelinePassCredential
	result *vc.VerifyResult
	err    error
}

func (f *fakeChainVerifier) VerifyChain(_ context.Context, head *vc.PipelinePassCredential) (*vc.VerifyResult, error) {
	f.calls = append(f.calls, head)
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

type storageCall struct {
	cred             *vc.PipelinePassCredential
	upstreamEndpoint string
}

type fakeStore struct {
	calls     []storageCall
	returnErr error
}

func (f *fakeStore) StoreIngressVC(_ context.Context, cred *vc.PipelinePassCredential, upstreamEndpoint string) error {
	f.calls = append(f.calls, storageCall{cred: cred, upstreamEndpoint: upstreamEndpoint})
	return f.returnErr
}

type signCall struct {
	payload     []byte
	inputHash   string
	outputHash  string
	predecessor *vc.PipelinePassCredential
}

type fakeSigner struct {
	calls      []signCall
	returnErr  error
	returnCred *vc.PipelinePassCredential
}

func (f *fakeSigner) SignChainPreserving(_ context.Context, payload []byte, inputHash, outputHash string, predecessor *vc.PipelinePassCredential) (*vc.PipelinePassCredential, error) {
	f.calls = append(f.calls, signCall{
		payload:     payload,
		inputHash:   inputHash,
		outputHash:  outputHash,
		predecessor: predecessor,
	})
	if f.returnErr != nil {
		return nil, f.returnErr
	}
	if f.returnCred != nil {
		return f.returnCred, nil
	}
	prev := ""
	if predecessor != nil {
		prev, _ = predecessor.Hash()
	}
	return vc.New(vc.CredentialFields{
		Issuer:    "did:example:process",
		ValidFrom: time.Now(),
		Subject: vc.CredentialSubjectFields{
			PipelineID:          "test-pipeline",
			ProcessID:           "test-process",
			TransformationClaim: vc.ClaimConvert,
			InputHash:           inputHash,
			OutputHash:          outputHash,
		},
		PreviousCredential: prev,
	})
}

type validateCall struct {
	payload []byte
	ref     vc.SchemaRef
}

type fakeValidator struct {
	calls     []validateCall
	returnErr error
}

func (f *fakeValidator) Validate(_ context.Context, payload []byte, ref vc.SchemaRef) error {
	f.calls = append(f.calls, validateCall{payload: payload, ref: ref})
	return f.returnErr
}

type fakeObserver struct {
	calls     []contract.ProcessEvent
	returnErr error
}

func (f *fakeObserver) OnProcessComplete(_ context.Context, ev contract.ProcessEvent) error {
	f.calls = append(f.calls, ev)
	return f.returnErr
}

type fakeFilter struct {
	pass bool
	err  error
}

func (f *fakeFilter) Apply(_ context.Context, _ []byte) (*filter.Result, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &filter.Result{Pass: f.pass}, nil
}

type fakeConverter struct {
	output []byte
	err    error
}

func (f *fakeConverter) Convert(_ context.Context, _ []byte) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.output, nil
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

func verifiedResult() *vc.VerifyResult {
	return &vc.VerifyResult{Overall: vc.ConfidenceVerified}
}

func makeSchemaRef() vc.SchemaRef {
	return vc.SchemaRef{
		ID:          "https://example.com/schema/v1",
		Type:        "JsonSchema",
		ContentHash: "sha256:" + hex.EncodeToString(sha256.New().Sum(nil)),
	}
}

// newIngressCred builds an ingress credential BOUND to the payload it
// travels with: credentialSubject.outputHash = sha256 over the payload
// bytes — the payload-credential binding the runtime enforces.
func newIngressCred(t *testing.T, payload []byte) *vc.PipelinePassCredential {
	t.Helper()
	cred, err := vc.New(vc.CredentialFields{
		Issuer:    "did:example:upstream",
		ValidFrom: time.Now(),
		Subject: vc.CredentialSubjectFields{
			PipelineID:          "test-pipeline",
			ProcessID:           "upstream-process",
			TransformationClaim: vc.ClaimConvert,
			OutputHash:          rawHash(payload),
		},
	})
	if err != nil {
		t.Fatalf("newIngressCred: %v", err)
	}
	return cred
}

// encodeEnvelope marshals credential+payload using the real codec.
func encodeEnvelope(t *testing.T, cred *vc.PipelinePassCredential, payload []byte) []byte {
	t.Helper()
	wire, err := envelopecodec.New().MarshalEnvelope(&contract.Envelope{
		Credential: cred,
		Payload:    payload,
		SequenceNo: 1,
	})
	if err != nil {
		t.Fatalf("encodeEnvelope: %v", err)
	}
	return wire
}

// encodeEnvelopeByRef crafts a proto wire envelope with absent payload field
// to simulate by-reference delivery.
func encodeEnvelopeByRef(t *testing.T, cred *vc.PipelinePassCredential) []byte {
	t.Helper()
	credJSON, err := cred.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	wire, err := proto.Marshal(&pipelinev1.Envelope{
		Credential: credJSON,
		SequenceNo: 1,
		// Payload field absent → nil after decode
	})
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	return wire
}

func rawHash(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// baseAdjacentConfig returns a minimal valid Config with VerificationAdjacent.
func baseAdjacentConfig(v *fakeVerifier, s *fakeStore, sig *fakeSigner) chained.Config {
	return chained.Config{
		Strategy:          contract.VerificationAdjacent,
		IngressConformant: true,
		UpstreamEndpoint:  "https://example.com/upstream",
		Codec:             envelopecodec.New(),
		Verifier:          v,
		Store:             s,
		Signer:            sig,
	}
}

// ---------------------------------------------------------------------------
// Construction validation
// ---------------------------------------------------------------------------

func TestNew_Validation(t *testing.T) {
	codec := envelopecodec.New()
	verifier := &fakeVerifier{result: verifiedResult()}
	chainVerifier := &fakeChainVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}

	tests := []struct {
		name    string
		cfg     chained.Config
		wantErr bool
	}{
		{
			name: "strategy None rejected",
			cfg: chained.Config{
				Strategy:          contract.VerificationNone,
				IngressConformant: true,
				UpstreamEndpoint:  "https://example.com",
				Codec:             codec,
				Verifier:          verifier,
				Store:             store,
				Signer:            signer,
			},
			wantErr: true,
		},
		{
			name: "strategy Unknown rejected",
			cfg: chained.Config{
				Strategy:          contract.VerificationUnknown,
				IngressConformant: true,
				UpstreamEndpoint:  "https://example.com",
				Codec:             codec,
				Verifier:          verifier,
				Store:             store,
				Signer:            signer,
			},
			wantErr: true,
		},
		{
			name: "ingress-conformant false rejected",
			cfg: chained.Config{
				Strategy:          contract.VerificationAdjacent,
				IngressConformant: false,
				UpstreamEndpoint:  "https://example.com",
				Codec:             codec,
				Verifier:          verifier,
				Store:             store,
				Signer:            signer,
			},
			wantErr: true,
		},
		{
			name: "missing UpstreamEndpoint rejected",
			cfg: chained.Config{
				Strategy:          contract.VerificationAdjacent,
				IngressConformant: true,
				UpstreamEndpoint:  "",
				Codec:             codec,
				Verifier:          verifier,
				Store:             store,
				Signer:            signer,
			},
			wantErr: true,
		},
		{
			name: "missing Codec rejected",
			cfg: chained.Config{
				Strategy:          contract.VerificationAdjacent,
				IngressConformant: true,
				UpstreamEndpoint:  "https://example.com",
				Verifier:          verifier,
				Store:             store,
				Signer:            signer,
			},
			wantErr: true,
		},
		{
			name: "missing Store rejected",
			cfg: chained.Config{
				Strategy:          contract.VerificationAdjacent,
				IngressConformant: true,
				UpstreamEndpoint:  "https://example.com",
				Codec:             codec,
				Verifier:          verifier,
				Signer:            signer,
			},
			wantErr: true,
		},
		{
			name: "missing Signer rejected",
			cfg: chained.Config{
				Strategy:          contract.VerificationAdjacent,
				IngressConformant: true,
				UpstreamEndpoint:  "https://example.com",
				Codec:             codec,
				Verifier:          verifier,
				Store:             store,
			},
			wantErr: true,
		},
		{
			name: "adjacent with missing Verifier rejected",
			cfg: chained.Config{
				Strategy:          contract.VerificationAdjacent,
				IngressConformant: true,
				UpstreamEndpoint:  "https://example.com",
				Codec:             codec,
				Store:             store,
				Signer:            signer,
			},
			wantErr: true,
		},
		{
			name: "full with missing ChainVerifier rejected",
			cfg: chained.Config{
				Strategy:          contract.VerificationFull,
				IngressConformant: true,
				UpstreamEndpoint:  "https://example.com",
				Codec:             codec,
				Store:             store,
				Signer:            signer,
			},
			wantErr: true,
		},
		{
			name: "InputValidator without InputSchemaRef rejected",
			cfg: chained.Config{
				Strategy:          contract.VerificationAdjacent,
				IngressConformant: true,
				UpstreamEndpoint:  "https://example.com",
				Codec:             codec,
				Verifier:          verifier,
				Store:             store,
				Signer:            signer,
				InputValidator:    &fakeValidator{},
				// InputSchemaRef zero value
			},
			wantErr: true,
		},
		{
			name: "OutputValidator without OutputSchemaRef rejected",
			cfg: chained.Config{
				Strategy:          contract.VerificationAdjacent,
				IngressConformant: true,
				UpstreamEndpoint:  "https://example.com",
				Codec:             codec,
				Verifier:          verifier,
				Store:             store,
				Signer:            signer,
				OutputValidator:   &fakeValidator{},
				// OutputSchemaRef zero value
			},
			wantErr: true,
		},
		{
			name: "valid adjacent config accepted",
			cfg: chained.Config{
				Strategy:          contract.VerificationAdjacent,
				IngressConformant: true,
				UpstreamEndpoint:  "https://example.com",
				Codec:             codec,
				Verifier:          verifier,
				Store:             store,
				Signer:            signer,
			},
			wantErr: false,
		},
		{
			name: "valid full config accepted",
			cfg: chained.Config{
				Strategy:          contract.VerificationFull,
				IngressConformant: true,
				UpstreamEndpoint:  "https://example.com",
				Codec:             codec,
				ChainVerifier:     chainVerifier,
				Store:             store,
				Signer:            signer,
			},
			wantErr: false,
		},
		{
			name: "valid adjacent with all optional fields accepted",
			cfg: chained.Config{
				Strategy:          contract.VerificationAdjacent,
				IngressConformant: true,
				UpstreamEndpoint:  "https://example.com",
				Codec:             codec,
				Verifier:          verifier,
				Store:             store,
				Signer:            signer,
				InputValidator:    &fakeValidator{},
				InputSchemaRef:    makeSchemaRef(),
				OutputValidator:   &fakeValidator{},
				OutputSchemaRef:   makeSchemaRef(),
			},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := chained.New(tc.cfg)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Happy path — VerificationAdjacent
// ---------------------------------------------------------------------------

func TestProcess_HappyPath_Adjacent(t *testing.T) {
	payload := []byte(`{"msg":"hello"}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}
	obs := &fakeObserver{}

	cfg := baseAdjacentConfig(verifier, store, signer)
	cfg.Observers = []contract.ProcessObserver{obs}
	p, err := chained.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("Process returned Go error: %v", goErr)
	}
	if result == nil {
		t.Fatal("result is nil")
	}

	if result.Status != contract.StatusPassed {
		t.Errorf("Status=%v, want StatusPassed", result.Status)
	}
	if len(result.Payload) == 0 {
		t.Error("Payload is empty")
	}
	if result.VC == nil {
		t.Error("VC is nil")
	}
	if result.Confidence == nil {
		t.Fatal("Confidence is nil")
	}
	if *result.Confidence != vc.ConfidenceVerified {
		t.Errorf("Confidence=%v, want ConfidenceVerified", *result.Confidence)
	}
	if result.Error != "" {
		t.Errorf("Error=%q on passed result, want empty", result.Error)
	}

	// Verifier called once
	if len(verifier.calls) != 1 {
		t.Fatalf("Verifier.Verify call count=%d, want 1", len(verifier.calls))
	}

	// Store called once with correct endpoint
	if len(store.calls) != 1 {
		t.Fatalf("Store.StoreIngressVC call count=%d, want 1", len(store.calls))
	}
	if store.calls[0].upstreamEndpoint != cfg.UpstreamEndpoint {
		t.Errorf("StoreIngressVC endpoint=%q, want %q", store.calls[0].upstreamEndpoint, cfg.UpstreamEndpoint)
	}

	// Signer called once; predecessor == ingress credential
	if len(signer.calls) != 1 {
		t.Fatalf("Signer.Sign call count=%d, want 1", len(signer.calls))
	}
	sc := signer.calls[0]
	if sc.predecessor == nil {
		t.Fatal("Signer.Sign predecessor is nil")
	}
	ingressHash, err := cred.Hash()
	if err != nil {
		t.Fatalf("cred.Hash: %v", err)
	}
	predHash, err := sc.predecessor.Hash()
	if err != nil {
		t.Fatalf("predecessor.Hash: %v", err)
	}
	if ingressHash != predHash {
		t.Errorf("predecessor hash=%q, want ingress hash=%q", predHash, ingressHash)
	}

	// inputHash / outputHash format
	if len(sc.inputHash) < 8 || sc.inputHash[:7] != "sha256:" {
		t.Errorf("inputHash=%q does not start with sha256:", sc.inputHash)
	}
	if len(sc.outputHash) < 8 || sc.outputHash[:7] != "sha256:" {
		t.Errorf("outputHash=%q does not start with sha256:", sc.outputHash)
	}
	// inputHash over original payload bytes
	if sc.inputHash != rawHash(payload) {
		t.Errorf("inputHash=%q, want %q", sc.inputHash, rawHash(payload))
	}

	// Observer notified once
	if len(obs.calls) != 1 {
		t.Errorf("Observer calls=%d, want 1", len(obs.calls))
	}
	if obs.calls[0].Result == nil {
		t.Error("Observer ProcessEvent.Result is nil")
	}
	if obs.calls[0].VCRef == "" {
		t.Error("Observer ProcessEvent.VCRef is empty on passed result")
	}
}

// ---------------------------------------------------------------------------
// Happy path — VerificationFull
// ---------------------------------------------------------------------------

func TestProcess_HappyPath_Full(t *testing.T) {
	payload := []byte(`{"msg":"full"}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	chainVerifier := &fakeChainVerifier{result: verifiedResult()}
	verifier := &fakeVerifier{result: verifiedResult()} // must NOT be called for VerificationFull
	store := &fakeStore{}
	signer := &fakeSigner{}

	cfg := chained.Config{
		Strategy:          contract.VerificationFull,
		IngressConformant: true,
		UpstreamEndpoint:  "https://example.com/upstream",
		Codec:             envelopecodec.New(),
		ChainVerifier:     chainVerifier,
		Verifier:          verifier,
		Store:             store,
		Signer:            signer,
	}
	p, err := chained.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("Process returned Go error: %v", goErr)
	}
	if result.Status != contract.StatusPassed {
		t.Errorf("Status=%v, want StatusPassed", result.Status)
	}

	// ChainVerifier called; Verifier NOT called
	if len(chainVerifier.calls) != 1 {
		t.Errorf("ChainVerifier.VerifyChain calls=%d, want 1", len(chainVerifier.calls))
	}
	if len(verifier.calls) != 0 {
		t.Errorf("Verifier.Verify must not be called for VerificationFull, got %d calls", len(verifier.calls))
	}
}

// ---------------------------------------------------------------------------
// Call-order test
// ---------------------------------------------------------------------------

// TestProcess_CallOrder uses recording fakes to assert the lifecycle order:
// verify → store → input-validate → filter → convert → output-validate → sign → observe.
func TestProcess_CallOrder(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}

	// Use a single ordered-call tracker via a shared slice pointer.
	var callLog []string
	logVerifier := &loggingVerifier{inner: verifier, log: &callLog, tag: "verify"}
	logStore := &loggingStore{inner: store, log: &callLog, tag: "store"}
	logInputV := &loggingValidator{log: &callLog, tag: "input-validate", returnErr: nil}
	logFilter := &loggingFilter{log: &callLog, tag: "filter", pass: true}
	logConverter := &loggingConverter{log: &callLog, tag: "convert", output: []byte(`{"x":1,"converted":true}`)}
	logOutputV := &loggingValidator{log: &callLog, tag: "output-validate", returnErr: nil}
	logSigner := &loggingSignerWrapper{inner: signer, log: &callLog, tag: "sign"}
	logObserver := &loggingObserver{log: &callLog, tag: "observe"}

	cfg := chained.Config{
		Strategy:          contract.VerificationAdjacent,
		IngressConformant: true,
		UpstreamEndpoint:  "https://example.com/upstream",
		Codec:             envelopecodec.New(),
		Verifier:          logVerifier,
		Store:             logStore,
		Signer:            logSigner,
		InputValidator:    logInputV,
		InputSchemaRef:    makeSchemaRef(),
		Filters:           []filter.Filter{logFilter},
		Converter:         logConverter,
		OutputValidator:   logOutputV,
		OutputSchemaRef:   makeSchemaRef(),
		Observers:         []contract.ProcessObserver{logObserver},
	}
	p, err := chained.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("Process returned Go error: %v", goErr)
	}
	if result.Status != contract.StatusPassed {
		t.Errorf("Status=%v, want StatusPassed; callLog=%v", result.Status, callLog)
	}

	want := []string{"verify", "store", "input-validate", "filter", "convert", "output-validate", "sign", "observe"}
	if len(callLog) != len(want) {
		t.Fatalf("callLog=%v, want %v", callLog, want)
	}
	for i, w := range want {
		if callLog[i] != w {
			t.Errorf("callLog[%d]=%q, want %q", i, callLog[i], w)
		}
	}
}

// Logging wrappers for call-order test.

type loggingVerifier struct {
	inner *fakeVerifier
	log   *[]string
	tag   string
}

func (l *loggingVerifier) Verify(ctx context.Context, cred *vc.PipelinePassCredential) (*vc.VerifyResult, error) {
	*l.log = append(*l.log, l.tag)
	return l.inner.Verify(ctx, cred)
}

type loggingStore struct {
	inner *fakeStore
	log   *[]string
	tag   string
}

func (l *loggingStore) StoreIngressVC(ctx context.Context, cred *vc.PipelinePassCredential, endpoint string) error {
	*l.log = append(*l.log, l.tag)
	return l.inner.StoreIngressVC(ctx, cred, endpoint)
}

type loggingValidator struct {
	log       *[]string
	tag       string
	returnErr error
	calls     []validateCall
}

func (l *loggingValidator) Validate(_ context.Context, payload []byte, ref vc.SchemaRef) error {
	*l.log = append(*l.log, l.tag)
	l.calls = append(l.calls, validateCall{payload: payload, ref: ref})
	return l.returnErr
}

type loggingFilter struct {
	log  *[]string
	tag  string
	pass bool
	err  error
}

func (l *loggingFilter) Apply(_ context.Context, _ []byte) (*filter.Result, error) {
	*l.log = append(*l.log, l.tag)
	if l.err != nil {
		return nil, l.err
	}
	return &filter.Result{Pass: l.pass}, nil
}

type loggingConverter struct {
	log    *[]string
	tag    string
	output []byte
	err    error
}

func (l *loggingConverter) Convert(_ context.Context, _ []byte) ([]byte, error) {
	*l.log = append(*l.log, l.tag)
	if l.err != nil {
		return nil, l.err
	}
	return l.output, nil
}

type loggingSignerWrapper struct {
	inner *fakeSigner
	log   *[]string
	tag   string
}

func (l *loggingSignerWrapper) SignChainPreserving(ctx context.Context, payload []byte, inputHash, outputHash string, predecessor *vc.PipelinePassCredential) (*vc.PipelinePassCredential, error) {
	*l.log = append(*l.log, l.tag)
	return l.inner.SignChainPreserving(ctx, payload, inputHash, outputHash, predecessor)
}

type loggingObserver struct {
	log *[]string
	tag string
}

func (l *loggingObserver) OnProcessComplete(_ context.Context, ev contract.ProcessEvent) error {
	*l.log = append(*l.log, l.tag)
	return nil
}

// ---------------------------------------------------------------------------
// Verification verdicts
// ---------------------------------------------------------------------------

func TestProcess_VerificationFailed_Errored(t *testing.T) {
	payload := []byte(`{"msg":"fail"}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{result: &vc.VerifyResult{Overall: vc.ConfidenceFailed}}
	store := &fakeStore{}
	signer := &fakeSigner{}

	p, _ := chained.New(baseAdjacentConfig(verifier, store, signer))
	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored", result.Status)
	}
	if result.Confidence == nil {
		t.Fatal("Confidence nil on errored result")
	}
	if *result.Confidence != vc.ConfidenceFailed {
		t.Errorf("Confidence=%v, want ConfidenceFailed", *result.Confidence)
	}
	if len(store.calls) != 0 {
		t.Errorf("Store called %d times, want 0 on failed verification", len(store.calls))
	}
	if len(signer.calls) != 0 {
		t.Errorf("Signer called %d times, want 0 on failed verification", len(signer.calls))
	}
}

func TestProcess_VerificationIndeterminate_Errored(t *testing.T) {
	payload := []byte(`{"msg":"indet"}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{result: &vc.VerifyResult{Overall: vc.ConfidenceIndeterminate}}
	store := &fakeStore{}
	signer := &fakeSigner{}

	p, _ := chained.New(baseAdjacentConfig(verifier, store, signer))
	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored (fail-closed on indeterminate)", result.Status)
	}
	if result.Confidence == nil || *result.Confidence != vc.ConfidenceIndeterminate {
		t.Errorf("Confidence=%v, want ConfidenceIndeterminate", result.Confidence)
	}
	if len(store.calls) != 0 {
		t.Errorf("Store called %d times, want 0", len(store.calls))
	}
}

func TestProcess_VerificationVerified_Proceeds(t *testing.T) {
	payload := []byte(`{"msg":"ok"}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}

	p, _ := chained.New(baseAdjacentConfig(verifier, store, signer))
	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusPassed {
		t.Errorf("Status=%v, want StatusPassed", result.Status)
	}
}

// ---------------------------------------------------------------------------
// Store failure
// ---------------------------------------------------------------------------

func TestProcess_StoreFails_Errored(t *testing.T) {
	payload := []byte(`{"msg":"store"}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{returnErr: errors.New("storage unavailable")}
	signer := &fakeSigner{}

	p, _ := chained.New(baseAdjacentConfig(verifier, store, signer))
	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored", result.Status)
	}
	if len(signer.calls) != 0 {
		t.Errorf("Signer called %d times after store failure, want 0", len(signer.calls))
	}
}

// ---------------------------------------------------------------------------
// Payload ↔ credential binding (sha256(payload) must equal the ingress
// credential's declared outputHash — chain continuity by construction)
// ---------------------------------------------------------------------------

func TestProcess_PayloadCredentialMismatch_Errored(t *testing.T) {
	// Credential bound to one byte string, envelope carrying another:
	// the tampered-payload case the binding check exists for.
	cred := newIngressCred(t, []byte(`{"genuine":true}`))
	wire := encodeEnvelope(t, cred, []byte(`{"tampered":true}`))

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}
	flt := &fakeFilter{pass: true}

	cfg := baseAdjacentConfig(verifier, store, signer)
	cfg.Filters = []filter.Filter{flt}
	p, err := chained.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Fatalf("Status=%v, want StatusErrored on payload/credential mismatch", result.Status)
	}
	if len(signer.calls) != 0 {
		t.Error("Signer must never run on tampered payload")
	}
	// The credential itself was genuinely verified; the verdict still rides.
	if result.Confidence == nil || *result.Confidence != vc.ConfidenceVerified {
		t.Errorf("Confidence=%v, want ConfidenceVerified (the credential was genuine; the payload was not)", result.Confidence)
	}
}

func TestProcess_PredecessorWithoutOutputHash_Errored(t *testing.T) {
	// A producing predecessor must declare outputHash; its absence makes the
	// binding undecidable — malformed predecessor, fail closed.
	payload := []byte(`{"x":1}`)
	cred, err := vc.New(vc.CredentialFields{
		Issuer:    "did:example:upstream",
		ValidFrom: time.Now(),
		Subject: vc.CredentialSubjectFields{
			PipelineID:          "test-pipeline",
			ProcessID:           "upstream-process",
			TransformationClaim: vc.ClaimConvert,
			// OutputHash deliberately absent.
		},
	})
	if err != nil {
		t.Fatalf("vc.New: %v", err)
	}
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}

	p, _ := chained.New(baseAdjacentConfig(verifier, store, signer))
	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored when the predecessor declares no outputHash", result.Status)
	}
	if len(signer.calls) != 0 {
		t.Error("Signer must not run without a decidable binding")
	}
}

// ---------------------------------------------------------------------------
// Cancellation during a stage propagates as a Go error
// ---------------------------------------------------------------------------

func TestProcess_StageCancellation_PropagatesGoError(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	// A verifier that reports the context's cancellation, as a real
	// resolver-backed verifier would mid-call.
	verifier := &fakeVerifier{err: context.Canceled}
	store := &fakeStore{}
	signer := &fakeSigner{}

	p, _ := chained.New(baseAdjacentConfig(verifier, store, signer))
	result, goErr := p.Process(context.Background(), wire)
	if !errors.Is(goErr, context.Canceled) {
		t.Fatalf("goErr=%v, want context.Canceled propagated (a cancelled stage is not a domain failure)", goErr)
	}
	if result != nil {
		t.Errorf("result=%v, want nil alongside the propagated cancellation", result)
	}
}

// ---------------------------------------------------------------------------
// By-reference payload (nil)
// ---------------------------------------------------------------------------

func TestProcess_ByRefPayload_Errored(t *testing.T) {
	cred := newIngressCred(t, []byte(`{"x":1}`))
	wire := encodeEnvelopeByRef(t, cred)

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}

	p, _ := chained.New(baseAdjacentConfig(verifier, store, signer))
	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored for nil payload", result.Status)
	}
}

// ---------------------------------------------------------------------------
// Input-schema validation failure
// ---------------------------------------------------------------------------

func TestProcess_InputValidation_Fails_Errored(t *testing.T) {
	payload := []byte(`{"msg":"bad"}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}
	inputV := &fakeValidator{returnErr: errors.New("schema violation")}

	cfg := baseAdjacentConfig(verifier, store, signer)
	cfg.InputValidator = inputV
	cfg.InputSchemaRef = makeSchemaRef()
	p, _ := chained.New(cfg)

	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored", result.Status)
	}
	if len(signer.calls) != 0 {
		t.Errorf("Signer called after input validation failure, want 0")
	}
}

// ---------------------------------------------------------------------------
// Filter: falsy → StatusFiltered
// ---------------------------------------------------------------------------

func TestProcess_FilterFalsy_Filtered(t *testing.T) {
	payload := []byte(`{"msg":"drop"}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}
	obs := &fakeObserver{}

	f, err := filterjsonata.New([]string{"false"})
	if err != nil {
		t.Fatalf("filter.New: %v", err)
	}

	cfg := baseAdjacentConfig(verifier, store, signer)
	cfg.Filters = []filter.Filter{f}
	cfg.Observers = []contract.ProcessObserver{obs}
	p, err := chained.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusFiltered {
		t.Errorf("Status=%v, want StatusFiltered", result.Status)
	}
	if result.FilteredAtStep != 0 {
		t.Errorf("FilteredAtStep=%d, want 0", result.FilteredAtStep)
	}
	// Confidence still set
	if result.Confidence == nil {
		t.Fatal("Confidence nil on filtered result")
	}
	// Signer not called
	if len(signer.calls) != 0 {
		t.Errorf("Signer called on filtered event, want 0")
	}
	// Observer notified
	if len(obs.calls) != 1 {
		t.Errorf("Observer calls=%d, want 1", len(obs.calls))
	}
}

// ---------------------------------------------------------------------------
// Multi-filter: second filter falsy → FilteredAtStep = 1
// ---------------------------------------------------------------------------

func TestProcess_FilterMulti_SecondFalsy_IndexOne(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}

	f1, _ := filterjsonata.New([]string{"true"})
	f2, _ := filterjsonata.New([]string{"false"})

	cfg := baseAdjacentConfig(verifier, store, signer)
	cfg.Filters = []filter.Filter{f1, f2}
	p, _ := chained.New(cfg)

	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusFiltered {
		t.Errorf("Status=%v, want StatusFiltered", result.Status)
	}
	if result.FilteredAtStep != 1 {
		t.Errorf("FilteredAtStep=%d, want 1", result.FilteredAtStep)
	}
}

// ---------------------------------------------------------------------------
// Filter error (step failure) vs falsy (intentional drop)
// ---------------------------------------------------------------------------

func TestProcess_FilterError_Errored(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}

	errFilter := &fakeFilter{err: errors.New("step failure")}

	cfg := baseAdjacentConfig(verifier, store, signer)
	cfg.Filters = []filter.Filter{errFilter}
	p, _ := chained.New(cfg)

	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored for filter step failure", result.Status)
	}
}

func TestProcess_FilterFalsy_NoError(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}

	// falsy = intentional drop, not a step error
	falsyFilter := &fakeFilter{pass: false, err: nil}

	cfg := baseAdjacentConfig(verifier, store, signer)
	cfg.Filters = []filter.Filter{falsyFilter}
	p, _ := chained.New(cfg)

	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusFiltered {
		t.Errorf("Status=%v, want StatusFiltered for falsy filter (not errored)", result.Status)
	}
}

// ---------------------------------------------------------------------------
// Nil converter → passthrough; inputHash == outputHash
// ---------------------------------------------------------------------------

func TestProcess_NilConverter_Passthrough(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}

	cfg := baseAdjacentConfig(verifier, store, signer)
	// Converter is nil — output == input payload
	p, _ := chained.New(cfg)

	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusPassed {
		t.Errorf("Status=%v, want StatusPassed", result.Status)
	}
	// hashes still computed
	if len(signer.calls) != 1 {
		t.Fatalf("Signer calls=%d, want 1", len(signer.calls))
	}
	sc := signer.calls[0]
	// Passthrough is byte-identical: with a nil converter the output IS the
	// input payload (the strict-decode stage is a gate, never a re-encoder),
	// so outputHash == inputHash == sha256 over the payload bytes — the
	// chain-continuity property worth pinning.
	wantHash := rawHash(payload)
	if sc.inputHash != wantHash {
		t.Errorf("inputHash=%q, want %q", sc.inputHash, wantHash)
	}
	if sc.outputHash != wantHash {
		t.Errorf("outputHash=%q, want %q (passthrough must be byte-identical)", sc.outputHash, wantHash)
	}
}

// ---------------------------------------------------------------------------
// Converter producing pathological output → strict-decode stage catches it
// ---------------------------------------------------------------------------

func TestProcess_ConverterDuplicateKeyOutput_Errored(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}

	// Duplicate-key JSON — real jsonata cannot produce this, but a fake can.
	dupKeyConverter := &fakeConverter{output: []byte(`{"a":1,"a":2}`)}

	cfg := baseAdjacentConfig(verifier, store, signer)
	cfg.Converter = dupKeyConverter
	p, _ := chained.New(cfg)

	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored; strict-decode must catch duplicate keys", result.Status)
	}
}

func TestProcess_ConverterTrailingDataOutput_Errored(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}

	trailingConverter := &fakeConverter{output: []byte(`{"a":1} {"b":2}`)}

	cfg := baseAdjacentConfig(verifier, store, signer)
	cfg.Converter = trailingConverter
	p, _ := chained.New(cfg)

	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored; strict-decode must catch trailing data", result.Status)
	}
}

// ---------------------------------------------------------------------------
// Empty converter output → StatusErrored
// ---------------------------------------------------------------------------

func TestProcess_EmptyConverterOutput_Errored(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}

	emptyConverter := &fakeConverter{output: []byte{}}

	cfg := baseAdjacentConfig(verifier, store, signer)
	cfg.Converter = emptyConverter
	p, _ := chained.New(cfg)

	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored for empty converter output", result.Status)
	}
}

// ---------------------------------------------------------------------------
// Output validation failure
// ---------------------------------------------------------------------------

func TestProcess_OutputValidation_Fails_Errored(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}
	outputV := &fakeValidator{returnErr: errors.New("output schema violation")}

	cfg := baseAdjacentConfig(verifier, store, signer)
	cfg.OutputValidator = outputV
	cfg.OutputSchemaRef = makeSchemaRef()
	p, _ := chained.New(cfg)

	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored", result.Status)
	}
	if len(signer.calls) != 0 {
		t.Errorf("Signer called after output validation failure, want 0")
	}
}

// ---------------------------------------------------------------------------
// Observer error → logged, status unchanged, all observers still invoked
// ---------------------------------------------------------------------------

func TestProcess_ObserverError_DoesNotPropagate(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}

	obs1 := &fakeObserver{returnErr: errors.New("observer failure")}
	obs2 := &fakeObserver{}

	cfg := baseAdjacentConfig(verifier, store, signer)
	cfg.Observers = []contract.ProcessObserver{obs1, obs2}
	p, _ := chained.New(cfg)

	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusPassed {
		t.Errorf("Status=%v, want StatusPassed (observer error must not change status)", result.Status)
	}
	// Both observers must have been called
	if len(obs1.calls) != 1 {
		t.Errorf("obs1 calls=%d, want 1", len(obs1.calls))
	}
	if len(obs2.calls) != 1 {
		t.Errorf("obs2 calls=%d, want 1 (must still be called after obs1 error)", len(obs2.calls))
	}
}

// Observer notified on StatusFiltered too.
func TestProcess_ObserverNotifiedOnFiltered(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}
	obs := &fakeObserver{}

	falsyFilter := &fakeFilter{pass: false}

	cfg := baseAdjacentConfig(verifier, store, signer)
	cfg.Filters = []filter.Filter{falsyFilter}
	cfg.Observers = []contract.ProcessObserver{obs}
	p, _ := chained.New(cfg)

	result, _ := p.Process(context.Background(), wire)
	if result.Status != contract.StatusFiltered {
		t.Errorf("Status=%v, want StatusFiltered", result.Status)
	}
	if len(obs.calls) != 1 {
		t.Errorf("Observer calls=%d, want 1 on filtered event", len(obs.calls))
	}
}

// Observer notified on StatusErrored too.
func TestProcess_ObserverNotifiedOnErrored(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{result: &vc.VerifyResult{Overall: vc.ConfidenceFailed}}
	store := &fakeStore{}
	signer := &fakeSigner{}
	obs := &fakeObserver{}

	cfg := baseAdjacentConfig(verifier, store, signer)
	cfg.Observers = []contract.ProcessObserver{obs}
	p, _ := chained.New(cfg)

	result, _ := p.Process(context.Background(), wire)
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored", result.Status)
	}
	if len(obs.calls) != 1 {
		t.Errorf("Observer calls=%d, want 1 on errored event", len(obs.calls))
	}
}

// ---------------------------------------------------------------------------
// Context cancellation propagates as Go error
// ---------------------------------------------------------------------------

func TestProcess_CtxCancelled_GoError(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before Process is called

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}

	p, _ := chained.New(baseAdjacentConfig(verifier, store, signer))
	result, goErr := p.Process(ctx, wire)
	// Cancellation is deterministically a Go error (the doc reserves the Go
	// error return for exactly this); pin it.
	if !errors.Is(goErr, context.Canceled) {
		t.Fatalf("goErr=%v, want context.Canceled", goErr)
	}
	if result != nil {
		t.Errorf("result=%v, want nil alongside the Go error", result)
	}
}

// ---------------------------------------------------------------------------
// Verification error paths (transport error → indeterminate; full strategy)
// ---------------------------------------------------------------------------

func TestProcess_VerifierError_IndeterminateErrored(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{err: errors.New("resolver unreachable")}
	store := &fakeStore{}
	signer := &fakeSigner{}

	p, _ := chained.New(baseAdjacentConfig(verifier, store, signer))
	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored", result.Status)
	}
	if result.Confidence == nil || *result.Confidence != vc.ConfidenceIndeterminate {
		t.Errorf("Confidence=%v, want ConfidenceIndeterminate (a verification transport error is the indeterminate verdict, never nil)", result.Confidence)
	}
	if len(store.calls) != 0 || len(signer.calls) != 0 {
		t.Error("store/sign must not run after a verification error")
	}
}

func TestProcess_FullStrategy_FailedVerdict_Errored(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	failed := vc.ConfidenceFailed
	chainVerifier := &fakeChainVerifier{result: &vc.VerifyResult{Overall: failed}}
	store := &fakeStore{}
	signer := &fakeSigner{}

	cfg := baseAdjacentConfig(nil, store, signer)
	cfg.Strategy = contract.VerificationFull
	cfg.Verifier = nil
	cfg.ChainVerifier = chainVerifier
	p, err := chained.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored", result.Status)
	}
	if result.Confidence == nil || *result.Confidence != vc.ConfidenceFailed {
		t.Errorf("Confidence=%v, want ConfidenceFailed", result.Confidence)
	}
}

func TestProcess_FullStrategy_ChainVerifyError_IndeterminateErrored(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	chainVerifier := &fakeChainVerifier{err: errors.New("chain hole: upstream unreachable")}
	store := &fakeStore{}
	signer := &fakeSigner{}

	cfg := baseAdjacentConfig(nil, store, signer)
	cfg.Strategy = contract.VerificationFull
	cfg.Verifier = nil
	cfg.ChainVerifier = chainVerifier
	p, err := chained.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored", result.Status)
	}
	if result.Confidence == nil || *result.Confidence != vc.ConfidenceIndeterminate {
		t.Errorf("Confidence=%v, want ConfidenceIndeterminate", result.Confidence)
	}
}

// ---------------------------------------------------------------------------
// Decode failure
// ---------------------------------------------------------------------------

func TestProcess_DecodeFails_Errored(t *testing.T) {
	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}

	p, _ := chained.New(baseAdjacentConfig(verifier, store, signer))
	result, goErr := p.Process(context.Background(), []byte("not-a-proto"))
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored on decode failure", result.Status)
	}
}

// ---------------------------------------------------------------------------
// Converter with real jsonata — end-to-end happy path
// ---------------------------------------------------------------------------

func TestProcess_RealConverter_EndToEnd(t *testing.T) {
	payload := []byte(`{"value":42}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	// Expression: pass through with an added field.
	conv, err := converterjsonata.New(`{"value": value, "doubled": value * 2}`)
	if err != nil {
		t.Fatalf("converterjsonata.New: %v", err)
	}

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}

	cfg := baseAdjacentConfig(verifier, store, signer)
	cfg.Converter = conv
	p, err := chained.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("Process returned Go error: %v", goErr)
	}
	if result.Status != contract.StatusPassed {
		t.Errorf("Status=%v, want StatusPassed", result.Status)
	}
	if len(result.Payload) == 0 {
		t.Error("Payload empty")
	}
}

// ---------------------------------------------------------------------------
// Signer failure → StatusErrored
// ---------------------------------------------------------------------------

func TestProcess_SignerFails_Errored(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{returnErr: errors.New("signing key unavailable")}

	p, _ := chained.New(baseAdjacentConfig(verifier, store, signer))
	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored on signer failure", result.Status)
	}
}

// ---------------------------------------------------------------------------
// ProcessEvent fields on passed result
// ---------------------------------------------------------------------------

func TestProcess_ProcessEventFields_Passed(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}
	obs := &fakeObserver{}

	fixedTime := time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)

	cfg := baseAdjacentConfig(verifier, store, signer)
	cfg.Observers = []contract.ProcessObserver{obs}
	cfg.Now = func() time.Time { return fixedTime }
	p, _ := chained.New(cfg)

	_, _ = p.Process(context.Background(), wire)

	if len(obs.calls) != 1 {
		t.Fatalf("Observer calls=%d, want 1", len(obs.calls))
	}
	ev := obs.calls[0]
	if ev.Result == nil {
		t.Error("ProcessEvent.Result is nil")
	}
	if ev.Timestamp != fixedTime {
		t.Errorf("Timestamp=%v, want %v", ev.Timestamp, fixedTime)
	}
	if ev.InputHash == "" {
		t.Error("ProcessEvent.InputHash is empty")
	}
	if ev.OutputHash == "" {
		t.Error("ProcessEvent.OutputHash is empty")
	}
	if ev.VCRef == "" {
		t.Error("ProcessEvent.VCRef is empty on passed result")
	}
	// VCRef must be sha256:<hex>
	if len(ev.VCRef) < 8 || ev.VCRef[:7] != "sha256:" {
		t.Errorf("VCRef=%q does not start with sha256:", ev.VCRef)
	}
}

// ---------------------------------------------------------------------------
// Converter error → StatusErrored
// ---------------------------------------------------------------------------

func TestProcess_ConverterFails_Errored(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}
	errConv := &fakeConverter{err: errors.New("convert error")}

	cfg := baseAdjacentConfig(verifier, store, signer)
	cfg.Converter = errConv
	p, _ := chained.New(cfg)

	result, goErr := p.Process(context.Background(), wire)
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored on converter failure", result.Status)
	}
}

// ---------------------------------------------------------------------------
// Hash format pin: "sha256:<64-hex-chars>"
// ---------------------------------------------------------------------------

func TestProcess_HashFormat(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := newIngressCred(t, payload)
	wire := encodeEnvelope(t, cred, payload)

	verifier := &fakeVerifier{result: verifiedResult()}
	store := &fakeStore{}
	signer := &fakeSigner{}

	p, _ := chained.New(baseAdjacentConfig(verifier, store, signer))
	_, _ = p.Process(context.Background(), wire)

	if len(signer.calls) != 1 {
		t.Fatalf("Signer calls=%d, want 1", len(signer.calls))
	}
	sc := signer.calls[0]
	checkHashFormat(t, "inputHash", sc.inputHash)
	checkHashFormat(t, "outputHash", sc.outputHash)
}

func checkHashFormat(t *testing.T, name, h string) {
	t.Helper()
	const prefix = "sha256:"
	if len(h) != len(prefix)+64 {
		t.Errorf("%s=%q: want len %d, got %d", name, h, len(prefix)+64, len(h))
		return
	}
	if h[:len(prefix)] != prefix {
		t.Errorf("%s=%q: does not start with %q", name, h, prefix)
	}
}

// ---------------------------------------------------------------------------
// Hash format consistency: rawHash helper uses same "sha256:<hex>" format
// ---------------------------------------------------------------------------

func TestHashFormat_Prefix(t *testing.T) {
	h := rawHash([]byte(`{"k":"v"}`))
	if len(h) != 7+64 {
		t.Errorf("rawHash len=%d, want %d", len(h), 7+64)
	}
	if h[:7] != "sha256:" {
		t.Errorf("rawHash=%q does not start with sha256:", h)
	}
}
