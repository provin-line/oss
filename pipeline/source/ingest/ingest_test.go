// Package ingest_test tests the Source Process ingest event processor.
//
// Test strategy: a recording fake SourceSigner (records args; returns a real
// FirstDrop credential so the issued VC can be hash-addressed and inspected),
// plus recording fake observers. There is no codec, verifier, or store to fake:
// a Source ingest process holds none of them.
package ingest_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/source/ingest"
	"github.com/provin-line/oss/vc"
)

// compile-time: *Processor must implement contract.EventProcessor.
var _ contract.EventProcessor = (*ingest.Processor)(nil)

// ---------------------------------------------------------------------------
// Recording fakes
// ---------------------------------------------------------------------------

type sourceSignCall struct {
	payload    []byte
	inputHash  string
	outputHash string
}

type fakeSourceSigner struct {
	calls      []sourceSignCall
	returnErr  error
	returnCred *vc.PipelinePassCredential
}

func (f *fakeSourceSigner) SignFirstDrop(_ context.Context, payload []byte, inputHash, outputHash string) (*vc.PipelinePassCredential, error) {
	f.calls = append(f.calls, sourceSignCall{payload: payload, inputHash: inputHash, outputHash: outputHash})
	if f.returnErr != nil {
		return nil, f.returnErr
	}
	if f.returnCred != nil {
		return f.returnCred, nil
	}
	// Default: a genuine FirstDrop — empty PreviousCredential (chain origin).
	// transformationClaim provin:convert is the typical N=0 ingestion claim
	// (process.source.firstdrop). The runtime hands the signer no claim; the
	// signer owns it — this mirrors the real vcdid signer.
	return vc.New(vc.CredentialFields{
		Issuer:    "did:example:source",
		ValidFrom: time.Now(),
		Subject: vc.CredentialSubjectFields{
			PipelineID:          "test-pipeline",
			ProcessID:           "ingest-process",
			TransformationClaim: vc.ClaimConvert,
			InputHash:           inputHash,
			OutputHash:          outputHash,
		},
		// PreviousCredential empty → FirstDrop.
	})
}

type fakeObserver struct {
	calls     []contract.ProcessEvent
	returnErr error
}

func (f *fakeObserver) OnProcessComplete(_ context.Context, ev contract.ProcessEvent) error {
	f.calls = append(f.calls, ev)
	return f.returnErr
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func rawHash(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// Construction validation
// ---------------------------------------------------------------------------

func TestNew_Validation(t *testing.T) {
	signer := &fakeSourceSigner{}

	tests := []struct {
		name    string
		cfg     ingest.Config
		wantErr bool
	}{
		{
			name:    "missing Signer rejected",
			cfg:     ingest.Config{},
			wantErr: true,
		},
		{
			name:    "valid minimal config accepted",
			cfg:     ingest.Config{Signer: signer},
			wantErr: false,
		},
		{
			name: "valid with observers accepted",
			cfg: ingest.Config{
				Signer:    signer,
				Observers: []contract.ProcessObserver{&fakeObserver{}},
			},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := ingest.New(tc.cfg)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// nil Logger and nil Now must default without panicking.
func TestNew_NilLoggerAndNowDefault(t *testing.T) {
	p, err := ingest.New(ingest.Config{Signer: &fakeSourceSigner{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// A Process call exercises both the default logger and the default clock.
	result, goErr := p.Process(context.Background(), []byte(`{"x":1}`))
	if goErr != nil {
		t.Fatalf("Process: %v", goErr)
	}
	if result.Status != contract.StatusPassed {
		t.Errorf("Status=%v, want StatusPassed", result.Status)
	}
}

// ---------------------------------------------------------------------------
// Happy path: raw external bytes → FirstDrop
// ---------------------------------------------------------------------------

func TestProcess_HappyPath(t *testing.T) {
	input := []byte(`{"msg":"hello"}`)

	signer := &fakeSourceSigner{}
	obs := &fakeObserver{}

	p, err := ingest.New(ingest.Config{
		Signer:    signer,
		Observers: []contract.ProcessObserver{obs},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, goErr := p.Process(context.Background(), input)
	if goErr != nil {
		t.Fatalf("Process returned Go error: %v", goErr)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	if result.Status != contract.StatusPassed {
		t.Errorf("Status=%v, want StatusPassed", result.Status)
	}
	if result.VC == nil {
		t.Fatal("VC is nil")
	}
	// Payload is the ingested bytes, verbatim.
	if string(result.Payload) != string(input) {
		t.Errorf("Payload=%q, want %q (verbatim ingestion)", result.Payload, input)
	}
	// VerificationNone: no verification ran, so Confidence stays nil.
	if result.Confidence != nil {
		t.Errorf("Confidence=%v, want nil (a Source declares VerificationNone)", *result.Confidence)
	}
	if result.Error != "" {
		t.Errorf("Error=%q on passed result, want empty", result.Error)
	}

	// Signer called once.
	if len(signer.calls) != 1 {
		t.Fatalf("SignFirstDrop call count=%d, want 1", len(signer.calls))
	}
	sc := signer.calls[0]
	// Verbatim ingestion: the signer receives the input bytes, and
	// inputHash == outputHash == sha256 over those bytes.
	if string(sc.payload) != string(input) {
		t.Errorf("signed payload=%q, want %q", sc.payload, input)
	}
	wantHash := rawHash(input)
	if sc.inputHash != wantHash {
		t.Errorf("inputHash=%q, want %q", sc.inputHash, wantHash)
	}
	if sc.outputHash != wantHash {
		t.Errorf("outputHash=%q, want %q (verbatim: output == input)", sc.outputHash, wantHash)
	}

	// End-to-end: the ISSUED FirstDrop's subject carries inputHash == outputHash
	// over the ingested bytes — the headline verbatim-ingestion invariant, pinned
	// at the credential boundary, not just the signer call boundary.
	subj, err := result.VC.Subject()
	if err != nil {
		t.Fatalf("result.VC.Subject(): %v", err)
	}
	if subj.InputHash != wantHash {
		t.Errorf("issued subject.InputHash=%q, want %q", subj.InputHash, wantHash)
	}
	if subj.OutputHash != wantHash {
		t.Errorf("issued subject.OutputHash=%q, want %q", subj.OutputHash, wantHash)
	}

	// Observer notified once with a non-empty IssuedVCRef.
	if len(obs.calls) != 1 {
		t.Fatalf("Observer calls=%d, want 1", len(obs.calls))
	}
	if obs.calls[0].IssuedVCRef == "" {
		t.Error("Observer ProcessEvent.IssuedVCRef is empty on passed result")
	}
}

// The issued credential is a FirstDrop: no previousCredential (chain origin).
func TestProcess_IssuesFirstDrop(t *testing.T) {
	signer := &fakeSourceSigner{}
	p, _ := ingest.New(ingest.Config{Signer: signer})

	result, goErr := p.Process(context.Background(), []byte(`{"x":1}`))
	if goErr != nil {
		t.Fatalf("Process: %v", goErr)
	}
	if result.VC == nil {
		t.Fatal("VC is nil")
	}
	if prev := result.VC.PreviousCredential(); prev != "" {
		t.Errorf("PreviousCredential=%q, want empty (a Source emits a FirstDrop chain origin)", prev)
	}
}

// A non-object JSON document (array) is still valid JSON and passes the gate:
// the strict-decode gate validates JSON well-formedness, not object shape — a
// Source signs canonical bytes, and `[1,2,3]` is valid JCS.
func TestProcess_JSONArrayInput_Passes(t *testing.T) {
	input := []byte(`[1,2,3]`)
	signer := &fakeSourceSigner{}
	p, _ := ingest.New(ingest.Config{Signer: signer})

	result, goErr := p.Process(context.Background(), input)
	if goErr != nil {
		t.Fatalf("Process: %v", goErr)
	}
	if result.Status != contract.StatusPassed {
		t.Errorf("Status=%v, want StatusPassed for a valid JSON array", result.Status)
	}
	// "Passes" must mean "reached the signer with the array bytes verbatim",
	// not merely "didn't error early".
	if len(signer.calls) != 1 {
		t.Fatalf("SignFirstDrop calls=%d, want 1", len(signer.calls))
	}
	if string(signer.calls[0].payload) != string(input) {
		t.Errorf("signed payload=%q, want %q", signer.calls[0].payload, input)
	}
}

// ---------------------------------------------------------------------------
// Empty input → StatusErrored (profile norm: never emit an empty FirstDrop)
// ---------------------------------------------------------------------------

func TestProcess_EmptyInput_Errored(t *testing.T) {
	signer := &fakeSourceSigner{}
	obs := &fakeObserver{}
	p, _ := ingest.New(ingest.Config{
		Signer:    signer,
		Observers: []contract.ProcessObserver{obs},
	})

	result, goErr := p.Process(context.Background(), []byte{})
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored on empty input", result.Status)
	}
	if len(signer.calls) != 0 {
		t.Errorf("Signer called %d times on empty input, want 0", len(signer.calls))
	}
	// Observer still notified on the errored outcome.
	if len(obs.calls) != 1 {
		t.Errorf("Observer calls=%d, want 1 on errored event", len(obs.calls))
	}
}

func TestProcess_NilInput_Errored(t *testing.T) {
	signer := &fakeSourceSigner{}
	p, _ := ingest.New(ingest.Config{Signer: signer})

	result, goErr := p.Process(context.Background(), nil)
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored on nil input", result.Status)
	}
}

// ---------------------------------------------------------------------------
// Strict-decode gate: malformed JSON must never be laundered into a FirstDrop
// ---------------------------------------------------------------------------

func TestProcess_DuplicateKeyInput_Errored(t *testing.T) {
	signer := &fakeSourceSigner{}
	p, _ := ingest.New(ingest.Config{Signer: signer})

	result, goErr := p.Process(context.Background(), []byte(`{"a":1,"a":2}`))
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored; strict-decode must catch duplicate keys", result.Status)
	}
	if len(signer.calls) != 0 {
		t.Error("Signer must not run on malformed input")
	}
}

func TestProcess_TrailingDataInput_Errored(t *testing.T) {
	signer := &fakeSourceSigner{}
	p, _ := ingest.New(ingest.Config{Signer: signer})

	result, goErr := p.Process(context.Background(), []byte(`{"a":1} {"b":2}`))
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored; strict-decode must catch trailing data", result.Status)
	}
	if len(signer.calls) != 0 {
		t.Error("Signer must not run on malformed input")
	}
}

func TestProcess_NotJSONInput_Errored(t *testing.T) {
	signer := &fakeSourceSigner{}
	p, _ := ingest.New(ingest.Config{Signer: signer})

	result, goErr := p.Process(context.Background(), []byte(`not json at all`))
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored on non-JSON input", result.Status)
	}
}

// ---------------------------------------------------------------------------
// Signer failure → StatusErrored
// ---------------------------------------------------------------------------

func TestProcess_SignerFails_Errored(t *testing.T) {
	signer := &fakeSourceSigner{returnErr: errors.New("signing key unavailable")}
	p, _ := ingest.New(ingest.Config{Signer: signer})

	result, goErr := p.Process(context.Background(), []byte(`{"x":1}`))
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusErrored {
		t.Errorf("Status=%v, want StatusErrored on signer failure", result.Status)
	}
}

// ---------------------------------------------------------------------------
// Cancellation propagates as a Go error
// ---------------------------------------------------------------------------

func TestProcess_CtxCancelled_GoError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before Process is called

	signer := &fakeSourceSigner{}
	p, _ := ingest.New(ingest.Config{Signer: signer})

	result, goErr := p.Process(ctx, []byte(`{"x":1}`))
	if !errors.Is(goErr, context.Canceled) {
		t.Fatalf("goErr=%v, want context.Canceled (the doc reserves the Go error for cancellation)", goErr)
	}
	if result != nil {
		t.Errorf("result=%v, want nil alongside the Go error", result)
	}
	if len(signer.calls) != 0 {
		t.Error("Signer must not run after pre-flight cancellation")
	}
}

// A signer that reports the context's cancellation mid-call propagates it as a
// Go error (not a StatusErrored domain failure) so the transport loop drains.
func TestProcess_SignerCancellation_PropagatesGoError(t *testing.T) {
	signer := &fakeSourceSigner{returnErr: context.Canceled}
	p, _ := ingest.New(ingest.Config{Signer: signer})

	result, goErr := p.Process(context.Background(), []byte(`{"x":1}`))
	if !errors.Is(goErr, context.Canceled) {
		t.Fatalf("goErr=%v, want context.Canceled propagated", goErr)
	}
	if result != nil {
		t.Errorf("result=%v, want nil alongside the propagated cancellation", result)
	}
}

// ---------------------------------------------------------------------------
// Observer behaviour
// ---------------------------------------------------------------------------

func TestProcess_ObserverError_DoesNotPropagate(t *testing.T) {
	signer := &fakeSourceSigner{}
	obs1 := &fakeObserver{returnErr: errors.New("observer failure")}
	obs2 := &fakeObserver{}

	p, _ := ingest.New(ingest.Config{
		Signer:    signer,
		Observers: []contract.ProcessObserver{obs1, obs2},
	})

	result, goErr := p.Process(context.Background(), []byte(`{"x":1}`))
	if goErr != nil {
		t.Fatalf("unexpected Go error: %v", goErr)
	}
	if result.Status != contract.StatusPassed {
		t.Errorf("Status=%v, want StatusPassed (observer error must not change status)", result.Status)
	}
	if len(obs1.calls) != 1 {
		t.Errorf("obs1 calls=%d, want 1", len(obs1.calls))
	}
	if len(obs2.calls) != 1 {
		t.Errorf("obs2 calls=%d, want 1 (must still be called after obs1 error)", len(obs2.calls))
	}
}

func TestProcess_ProcessEventFields_Passed(t *testing.T) {
	input := []byte(`{"x":1}`)
	signer := &fakeSourceSigner{}
	obs := &fakeObserver{}

	fixedTime := time.Date(2026, 6, 13, 0, 0, 0, 0, time.UTC)

	p, _ := ingest.New(ingest.Config{
		Signer:    signer,
		Observers: []contract.ProcessObserver{obs},
		Now:       func() time.Time { return fixedTime },
	})

	_, _ = p.Process(context.Background(), input)

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
	wantHash := rawHash(input)
	if ev.InputHash != wantHash {
		t.Errorf("InputHash=%q, want %q", ev.InputHash, wantHash)
	}
	if ev.OutputHash != wantHash {
		t.Errorf("OutputHash=%q, want %q", ev.OutputHash, wantHash)
	}
	if ev.IssuedVCRef == "" {
		t.Error("ProcessEvent.IssuedVCRef is empty on passed result")
	}
	if len(ev.IssuedVCRef) < 8 || ev.IssuedVCRef[:7] != "sha256:" {
		t.Errorf("IssuedVCRef=%q does not start with sha256:", ev.IssuedVCRef)
	}
}

// ---------------------------------------------------------------------------
// Hash format pin: "sha256:<64-hex-chars>"
// ---------------------------------------------------------------------------

func TestProcess_HashFormat(t *testing.T) {
	signer := &fakeSourceSigner{}
	p, _ := ingest.New(ingest.Config{Signer: signer})

	_, _ = p.Process(context.Background(), []byte(`{"x":1}`))

	if len(signer.calls) != 1 {
		t.Fatalf("Signer calls=%d, want 1", len(signer.calls))
	}
	sc := signer.calls[0]
	const prefix = "sha256:"
	for _, h := range []struct {
		name, val string
	}{{"inputHash", sc.inputHash}, {"outputHash", sc.outputHash}} {
		if len(h.val) != len(prefix)+64 {
			t.Errorf("%s=%q: want len %d, got %d", h.name, h.val, len(prefix)+64, len(h.val))
			continue
		}
		if h.val[:len(prefix)] != prefix {
			t.Errorf("%s=%q: does not start with %q", h.name, h.val, prefix)
		}
	}
}
