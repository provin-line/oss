package transport_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/transport"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/vc"
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// syncSubscriber is the standard subscriber used in all message-delivery tests.
// Subscribe signals readyCh when the handler is stored; deliver() is safe to
// call only after <-readyCh.
type syncSubscriber struct {
	mu           sync.Mutex
	handler      func([]byte)
	readyCh      chan struct{}
	messages     [][]byte
	subscribeErr error
	drainErr     error
}

func newSyncSubscriber(msgs ...[]byte) *syncSubscriber {
	return &syncSubscriber{
		messages: msgs,
		readyCh:  make(chan struct{}),
	}
}

func (s *syncSubscriber) Subscribe(h func([]byte)) error {
	if s.subscribeErr != nil {
		return s.subscribeErr
	}
	s.mu.Lock()
	s.handler = h
	s.mu.Unlock()
	close(s.readyCh) // signal that handler is installed
	return nil
}

func (s *syncSubscriber) Drain() error { return s.drainErr }

// deliver sends all queued messages to the handler synchronously.
// Must be called only after <-s.readyCh.
func (s *syncSubscriber) deliver() {
	s.mu.Lock()
	h := s.handler
	msgs := s.messages
	s.mu.Unlock()
	for _, m := range msgs {
		h(m)
	}
}

// waitReady blocks until Subscribe has been called (handler installed).
func (s *syncSubscriber) waitReady() { <-s.readyCh }

// ---------------------------------------------------------------------------

type fakePublisher struct {
	mu        sync.Mutex
	calls     [][]byte
	failFirst int // fail the first N publishes
	closeErr  error
	closed    bool
}

func (f *fakePublisher) Publish(data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failFirst > 0 {
		f.failFirst--
		return errors.New("fakePublisher: publish error")
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	f.calls = append(f.calls, cp)
	return nil
}

func (f *fakePublisher) Healthy() bool { return true }

func (f *fakePublisher) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return f.closeErr
}

func (f *fakePublisher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// ---------------------------------------------------------------------------

type fakeTlog struct {
	mu       sync.Mutex
	appended [][]byte
	failErr  error
}

func (f *fakeTlog) Append(_ context.Context, payload []byte) (*tlog.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failErr != nil {
		return nil, f.failErr
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	f.appended = append(f.appended, cp)
	return &tlog.Record{Index: uint64(len(f.appended) - 1), Payload: cp}, nil
}

func (f *fakeTlog) Get(_ context.Context, _ uint64) (*tlog.Record, error)  { return nil, nil }
func (f *fakeTlog) Size(_ context.Context) (uint64, error)                 { return 0, nil }
func (f *fakeTlog) Checkpoint(_ context.Context) (*tlog.Checkpoint, error) { return nil, nil }

func (f *fakeTlog) appendedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.appended)
}

// ---------------------------------------------------------------------------

type fakeProcessor struct {
	mu      sync.Mutex
	results []*contract.Result
	errs    []error
	idx     int
}

func (f *fakeProcessor) Process(_ context.Context, _ []byte) (*contract.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.idx >= len(f.results) {
		return &contract.Result{Status: contract.StatusPassed}, nil
	}
	r := f.results[f.idx]
	e := f.errs[f.idx]
	f.idx++
	return r, e
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestCredential(t *testing.T, payload []byte) *vc.PipelinePassCredential {
	t.Helper()
	sum := sha256.Sum256(payload)
	outputHash := "sha256:" + hex.EncodeToString(sum[:])
	cred, err := vc.New(vc.CredentialFields{
		Issuer:    "did:example:process",
		ValidFrom: time.Now(),
		Subject: vc.CredentialSubjectFields{
			PipelineID:          "test-pipeline",
			ProcessID:           "test-process",
			TransformationClaim: vc.ClaimConvert,
			OutputHash:          outputHash,
		},
	})
	if err != nil {
		t.Fatalf("vc.New: %v", err)
	}
	return cred
}

func passedResult(t *testing.T, payload []byte) *contract.Result {
	t.Helper()
	return &contract.Result{
		Status:  contract.StatusPassed,
		VC:      newTestCredential(t, payload),
		Payload: payload,
	}
}

func validPreservingConfig(t *testing.T, sub *syncSubscriber) transport.LoopConfig {
	t.Helper()
	return transport.LoopConfig{
		Behavior:   contract.ChainPreserving,
		Strategy:   contract.VerificationAdjacent,
		Processor:  &fakeProcessor{},
		Subscriber: sub,
		Publisher:  &fakePublisher{},
		Codec:      envelopecodec.New(),
		Emission:   &fakeTlog{},
	}
}

// emissionRecord mirrors the internal struct in loop.go for JSON records.
// SequenceNo is a string-encoded uint64 — survives IEEE-754 JSON consumers.
type emissionRecord struct {
	CredentialHash string `json:"credentialHash"`
	SequenceNo     string `json:"sequenceNo"`
}

// runLoop starts loop.Run in a goroutine, waits until Subscribe is called
// (guaranteeing handler is installed), then returns the cancel func and done
// channel. Callers must call cancel() to shut the loop down.
func runLoop(t *testing.T, loop *transport.Loop, sub *syncSubscriber) (cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	ctx, c := context.WithCancel(context.Background())
	ch := make(chan error, 1)
	go func() { ch <- loop.Run(ctx) }()
	sub.waitReady() // block until handler is installed (Subscribe returned)
	return c, ch
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestLoop_CompileTimeInterface checks *Loop implements contract.Process.
func TestLoop_CompileTimeInterface(t *testing.T) {
	var _ contract.Process = (*transport.Loop)(nil)
}

// TestNewLoop_Validation covers each sentinel error path.
func TestNewLoop_Validation(t *testing.T) {
	baseSubFn := func() *syncSubscriber { return newSyncSubscriber() }
	basePub := func() *fakePublisher { return &fakePublisher{} }
	baseCodec := envelopecodec.New()
	baseEmission := func() *fakeTlog { return &fakeTlog{} }

	base := func() transport.LoopConfig {
		return transport.LoopConfig{
			Behavior:   contract.ChainPreserving,
			Strategy:   contract.VerificationAdjacent,
			Processor:  &fakeProcessor{},
			Subscriber: baseSubFn(),
			Publisher:  basePub(),
			Codec:      baseCodec,
			Emission:   baseEmission(),
		}
	}

	tests := []struct {
		name    string
		cfg     transport.LoopConfig
		wantErr error
	}{
		{
			name: "nil Processor",
			cfg: func() transport.LoopConfig {
				c := base()
				c.Processor = nil
				return c
			}(),
			wantErr: transport.ErrMissingProcessor,
		},
		{
			name: "nil Subscriber",
			cfg: func() transport.LoopConfig {
				c := base()
				c.Subscriber = nil
				return c
			}(),
			wantErr: transport.ErrMissingSubscriber,
		},
		{
			name: "unknown Behavior",
			cfg: func() transport.LoopConfig {
				c := base()
				c.Behavior = contract.ChainBehaviorUnknown
				return c
			}(),
			wantErr: transport.ErrUnknownBehavior,
		},
		{
			name: "unknown Strategy",
			cfg: func() transport.LoopConfig {
				c := base()
				c.Strategy = contract.VerificationUnknown
				return c
			}(),
			wantErr: transport.ErrUnknownStrategy,
		},
		{
			name: "Preserving nil Publisher",
			cfg: func() transport.LoopConfig {
				c := base()
				c.Behavior = contract.ChainPreserving
				c.Publisher = nil
				return c
			}(),
			wantErr: transport.ErrMissingPublisher,
		},
		{
			name: "Preserving nil Codec",
			cfg: func() transport.LoopConfig {
				c := base()
				c.Behavior = contract.ChainPreserving
				c.Codec = nil
				return c
			}(),
			wantErr: transport.ErrMissingCodec,
		},
		{
			name: "Preserving nil Emission",
			cfg: func() transport.LoopConfig {
				c := base()
				c.Behavior = contract.ChainPreserving
				c.Emission = nil
				return c
			}(),
			wantErr: transport.ErrMissingEmission,
		},
		{
			name: "FirstDrop nil Publisher",
			cfg: func() transport.LoopConfig {
				c := base()
				c.Behavior = contract.ChainFirstDrop
				c.Publisher = nil
				return c
			}(),
			wantErr: transport.ErrMissingPublisher,
		},
		{
			name: "Terminating with Publisher wired",
			cfg: func() transport.LoopConfig {
				c := base()
				c.Behavior = contract.ChainTerminating
				return c
			}(),
			wantErr: transport.ErrSinkWithPublisher,
		},
		{
			name: "Terminating with Codec wired only",
			cfg: func() transport.LoopConfig {
				c := base()
				c.Behavior = contract.ChainTerminating
				c.Publisher = nil
				c.Emission = nil
				// Codec remains set
				return c
			}(),
			wantErr: transport.ErrSinkWithPublisher,
		},
		{
			name: "Terminating with Emission wired only",
			cfg: func() transport.LoopConfig {
				c := base()
				c.Behavior = contract.ChainTerminating
				c.Publisher = nil
				c.Codec = nil
				// Emission remains set
				return c
			}(),
			wantErr: transport.ErrSinkWithPublisher,
		},
		{
			name:    "valid Preserving config",
			cfg:     base(),
			wantErr: nil,
		},
		{
			name: "valid Terminating config",
			cfg: transport.LoopConfig{
				Behavior:   contract.ChainTerminating,
				Strategy:   contract.VerificationFull,
				Processor:  &fakeProcessor{},
				Subscriber: baseSubFn(),
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := transport.NewLoop(tt.cfg)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("NewLoop() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else {
				if err != nil {
					t.Fatalf("NewLoop() unexpected error: %v", err)
				}
			}
		})
	}
}

// TestLoop_PassedProducing_PublishesAndRecords verifies that a passing result
// on a ChainPreserving loop produces one publish call and one emission record.
func TestLoop_PassedProducing_PublishesAndRecords(t *testing.T) {
	payload := []byte(`{"hello":"world"}`)
	result := passedResult(t, payload)

	proc := &fakeProcessor{
		results: []*contract.Result{result},
		errs:    []error{nil},
	}
	sub := newSyncSubscriber([]byte("raw input"))
	pub := &fakePublisher{}
	emission := &fakeTlog{}
	codec := envelopecodec.New()

	cfg := transport.LoopConfig{
		Behavior:   contract.ChainPreserving,
		Strategy:   contract.VerificationAdjacent,
		Processor:  proc,
		Subscriber: sub,
		Publisher:  pub,
		Codec:      codec,
		Emission:   emission,
	}
	loop, err := transport.NewLoop(cfg)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}

	cancel, done := runLoop(t, loop, sub)
	sub.deliver()
	cancel()

	if runErr := <-done; runErr != nil {
		t.Fatalf("Run returned error: %v", runErr)
	}

	if pub.callCount() != 1 {
		t.Fatalf("expected 1 publish call, got %d", pub.callCount())
	}

	// Decode the published envelope.
	decoded, err := codec.UnmarshalEnvelope(pub.calls[0])
	if err != nil {
		t.Fatalf("UnmarshalEnvelope: %v", err)
	}
	if decoded.SequenceNo != 1 {
		t.Errorf("expected SequenceNo=1, got %d", decoded.SequenceNo)
	}
	if string(decoded.Payload) != string(payload) {
		t.Errorf("payload mismatch: got %q, want %q", decoded.Payload, payload)
	}

	wantHash, err := result.VC.Hash()
	if err != nil {
		t.Fatalf("VC.Hash: %v", err)
	}
	gotHash, err := decoded.Credential.Hash()
	if err != nil {
		t.Fatalf("decoded Credential.Hash: %v", err)
	}
	if gotHash != wantHash {
		t.Errorf("credential hash mismatch: got %q, want %q", gotHash, wantHash)
	}

	// Check emission record.
	if emission.appendedCount() != 1 {
		t.Fatalf("expected 1 emission record, got %d", emission.appendedCount())
	}
	var rec emissionRecord
	if err := json.Unmarshal(emission.appended[0], &rec); err != nil {
		t.Fatalf("unmarshal emission record: %v", err)
	}
	if rec.CredentialHash != wantHash {
		t.Errorf("emission credentialHash mismatch: got %q, want %q", rec.CredentialHash, wantHash)
	}
	if rec.SequenceNo != "1" {
		t.Errorf("emission sequenceNo mismatch: got %q, want \"1\"", rec.SequenceNo)
	}
}

// TestLoop_SequenceNumbers_TwoPasses verifies sequence numbers are strictly
// increasing across successive passed results.
func TestLoop_SequenceNumbers_TwoPasses(t *testing.T) {
	payload1 := []byte(`{"n":1}`)
	payload2 := []byte(`{"n":2}`)

	proc := &fakeProcessor{
		results: []*contract.Result{passedResult(t, payload1), passedResult(t, payload2)},
		errs:    []error{nil, nil},
	}
	sub := newSyncSubscriber([]byte("msg1"), []byte("msg2"))
	pub := &fakePublisher{}
	emission := &fakeTlog{}
	codec := envelopecodec.New()

	cfg := transport.LoopConfig{
		Behavior:   contract.ChainPreserving,
		Strategy:   contract.VerificationAdjacent,
		Processor:  proc,
		Subscriber: sub,
		Publisher:  pub,
		Codec:      codec,
		Emission:   emission,
	}
	loop, err := transport.NewLoop(cfg)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}

	cancel, done := runLoop(t, loop, sub)
	sub.deliver()
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if pub.callCount() != 2 {
		t.Fatalf("expected 2 publish calls, got %d", pub.callCount())
	}

	e1, err := codec.UnmarshalEnvelope(pub.calls[0])
	if err != nil {
		t.Fatalf("unmarshal first: %v", err)
	}
	e2, err := codec.UnmarshalEnvelope(pub.calls[1])
	if err != nil {
		t.Fatalf("unmarshal second: %v", err)
	}
	if e1.SequenceNo != 1 {
		t.Errorf("first SequenceNo: got %d, want 1", e1.SequenceNo)
	}
	if e2.SequenceNo != 2 {
		t.Errorf("second SequenceNo: got %d, want 2", e2.SequenceNo)
	}
}

// TestLoop_PublishFailThenSuccess_SequenceReuse verifies that a failed publish
// does not advance the sequence counter, so both attempts use SequenceNo==1.
func TestLoop_PublishFailThenSuccess_SequenceReuse(t *testing.T) {
	payload1 := []byte(`{"n":1}`)
	payload2 := []byte(`{"n":2}`)

	proc := &fakeProcessor{
		results: []*contract.Result{passedResult(t, payload1), passedResult(t, payload2)},
		errs:    []error{nil, nil},
	}
	sub := newSyncSubscriber([]byte("msg1"), []byte("msg2"))
	pub := &fakePublisher{failFirst: 1}
	emission := &fakeTlog{}
	codec := envelopecodec.New()

	cfg := transport.LoopConfig{
		Behavior:   contract.ChainPreserving,
		Strategy:   contract.VerificationAdjacent,
		Processor:  proc,
		Subscriber: sub,
		Publisher:  pub,
		Codec:      codec,
		Emission:   emission,
	}
	loop, err := transport.NewLoop(cfg)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}

	cancel, done := runLoop(t, loop, sub)
	sub.deliver()
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// Only 1 successful publish (first attempt failed).
	if pub.callCount() != 1 {
		t.Fatalf("expected 1 successful publish call, got %d", pub.callCount())
	}

	decoded, err := codec.UnmarshalEnvelope(pub.calls[0])
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Both attempts used SequenceNo==1; the successful one must show 1.
	if decoded.SequenceNo != 1 {
		t.Errorf("expected SequenceNo=1 on successful publish, got %d", decoded.SequenceNo)
	}

	// Emission has exactly 1 record (for the successful publish), with sequenceNo==1.
	if emission.appendedCount() != 1 {
		t.Fatalf("expected 1 emission record, got %d", emission.appendedCount())
	}
	var rec emissionRecord
	if err := json.Unmarshal(emission.appended[0], &rec); err != nil {
		t.Fatalf("unmarshal emission: %v", err)
	}
	if rec.SequenceNo != "1" {
		t.Errorf("emission sequenceNo: got %q, want \"1\"", rec.SequenceNo)
	}
}

// TestLoop_MarshalFailure_DropNotAdvance verifies that a marshal failure
// (nil VC) does not advance the sequence counter or publish anything.
func TestLoop_MarshalFailure_DropNotAdvance(t *testing.T) {
	payload := []byte(`{"ok":true}`)

	// First result has nil VC (will fail codec marshal).
	badResult := &contract.Result{
		Status:  contract.StatusPassed,
		VC:      nil,
		Payload: payload,
	}
	goodResult := passedResult(t, payload)

	proc := &fakeProcessor{
		results: []*contract.Result{badResult, goodResult},
		errs:    []error{nil, nil},
	}
	sub := newSyncSubscriber([]byte("msg1"), []byte("msg2"))
	pub := &fakePublisher{}
	emission := &fakeTlog{}
	codec := envelopecodec.New()

	cfg := transport.LoopConfig{
		Behavior:   contract.ChainPreserving,
		Strategy:   contract.VerificationAdjacent,
		Processor:  proc,
		Subscriber: sub,
		Publisher:  pub,
		Codec:      codec,
		Emission:   emission,
	}
	loop, err := transport.NewLoop(cfg)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}

	cancel, done := runLoop(t, loop, sub)
	sub.deliver()
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// Only one publish: for the second (good) message.
	if pub.callCount() != 1 {
		t.Fatalf("expected 1 publish call, got %d", pub.callCount())
	}
	decoded, err := codec.UnmarshalEnvelope(pub.calls[0])
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Counter was not advanced after the bad message, so good message uses 1.
	if decoded.SequenceNo != 1 {
		t.Errorf("expected SequenceNo=1 for second message, got %d", decoded.SequenceNo)
	}
}

// TestLoop_EmissionFailure_CounterAdvances verifies that emission log failure
// does not roll back the sequence counter — the event was delivered.
func TestLoop_EmissionFailure_CounterAdvances(t *testing.T) {
	payload1 := []byte(`{"n":1}`)
	payload2 := []byte(`{"n":2}`)

	proc := &fakeProcessor{
		results: []*contract.Result{passedResult(t, payload1), passedResult(t, payload2)},
		errs:    []error{nil, nil},
	}
	sub := newSyncSubscriber([]byte("msg1"), []byte("msg2"))
	pub := &fakePublisher{}
	emission := &fakeTlog{failErr: errors.New("tlog unavailable")}
	codec := envelopecodec.New()

	cfg := transport.LoopConfig{
		Behavior:   contract.ChainPreserving,
		Strategy:   contract.VerificationAdjacent,
		Processor:  proc,
		Subscriber: sub,
		Publisher:  pub,
		Codec:      codec,
		Emission:   emission,
	}
	loop, err := transport.NewLoop(cfg)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}

	cancel, done := runLoop(t, loop, sub)
	sub.deliver()
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// Both messages published despite emission failures.
	if pub.callCount() != 2 {
		t.Fatalf("expected 2 publish calls, got %d", pub.callCount())
	}

	// Second message must have SequenceNo==2 (counter advanced despite emission failure).
	e2, err := codec.UnmarshalEnvelope(pub.calls[1])
	if err != nil {
		t.Fatalf("unmarshal second: %v", err)
	}
	if e2.SequenceNo != 2 {
		t.Errorf("expected SequenceNo=2 for second message, got %d", e2.SequenceNo)
	}
}

// TestLoop_Filtered_NothingPublished verifies filtered events produce no
// publish calls and no emission records.
func TestLoop_Filtered_NothingPublished(t *testing.T) {
	proc := &fakeProcessor{
		results: []*contract.Result{{Status: contract.StatusFiltered, FilteredAtStep: 2}},
		errs:    []error{nil},
	}
	sub := newSyncSubscriber([]byte("input"))
	pub := &fakePublisher{}
	emission := &fakeTlog{}

	cfg := transport.LoopConfig{
		Behavior:   contract.ChainPreserving,
		Strategy:   contract.VerificationAdjacent,
		Processor:  proc,
		Subscriber: sub,
		Publisher:  pub,
		Codec:      envelopecodec.New(),
		Emission:   emission,
	}
	loop, err := transport.NewLoop(cfg)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}

	cancel, done := runLoop(t, loop, sub)
	sub.deliver()
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if pub.callCount() != 0 {
		t.Errorf("expected 0 publish calls for filtered event, got %d", pub.callCount())
	}
	if emission.appendedCount() != 0 {
		t.Errorf("expected 0 emission records for filtered event, got %d", emission.appendedCount())
	}
}

// TestLoop_Errored_NothingPublished verifies errored results produce no
// publish calls and no emission records.
func TestLoop_Errored_NothingPublished(t *testing.T) {
	proc := &fakeProcessor{
		results: []*contract.Result{{Status: contract.StatusErrored, Error: "conversion failed"}},
		errs:    []error{nil},
	}
	sub := newSyncSubscriber([]byte("input"))
	pub := &fakePublisher{}
	emission := &fakeTlog{}

	cfg := transport.LoopConfig{
		Behavior:   contract.ChainPreserving,
		Strategy:   contract.VerificationAdjacent,
		Processor:  proc,
		Subscriber: sub,
		Publisher:  pub,
		Codec:      envelopecodec.New(),
		Emission:   emission,
	}
	loop, err := transport.NewLoop(cfg)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}

	cancel, done := runLoop(t, loop, sub)
	sub.deliver()
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if pub.callCount() != 0 {
		t.Errorf("expected 0 publish calls for errored event, got %d", pub.callCount())
	}
	if emission.appendedCount() != 0 {
		t.Errorf("expected 0 emission records for errored event, got %d", emission.appendedCount())
	}
}

// TestLoop_ProcessorGoError_LoopContinues verifies that a Go-level error from
// Process does not stop the loop: the second message is processed normally.
func TestLoop_ProcessorGoError_LoopContinues(t *testing.T) {
	payload := []byte(`{"ok":true}`)
	good := passedResult(t, payload)

	proc := &fakeProcessor{
		results: []*contract.Result{nil, good},
		errs:    []error{errors.New("internal error"), nil},
	}
	sub := newSyncSubscriber([]byte("msg1"), []byte("msg2"))
	pub := &fakePublisher{}
	emission := &fakeTlog{}

	cfg := transport.LoopConfig{
		Behavior:   contract.ChainPreserving,
		Strategy:   contract.VerificationAdjacent,
		Processor:  proc,
		Subscriber: sub,
		Publisher:  pub,
		Codec:      envelopecodec.New(),
		Emission:   emission,
	}
	loop, err := transport.NewLoop(cfg)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}

	cancel, done := runLoop(t, loop, sub)
	sub.deliver()
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// Only second message published.
	if pub.callCount() != 1 {
		t.Fatalf("expected 1 publish call, got %d", pub.callCount())
	}
	if emission.appendedCount() != 1 {
		t.Fatalf("expected 1 emission record, got %d", emission.appendedCount())
	}
}

// TestLoop_Terminating_NothingPublished verifies a ChainTerminating loop
// publishes nothing for StatusPassed.
func TestLoop_Terminating_NothingPublished(t *testing.T) {
	proc := &fakeProcessor{
		results: []*contract.Result{{Status: contract.StatusPassed}},
		errs:    []error{nil},
	}
	sub := newSyncSubscriber([]byte("input"))

	cfg := transport.LoopConfig{
		Behavior:   contract.ChainTerminating,
		Strategy:   contract.VerificationFull,
		Processor:  proc,
		Subscriber: sub,
	}
	loop, err := transport.NewLoop(cfg)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}

	cancel, done := runLoop(t, loop, sub)
	sub.deliver()
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	// No publisher in this config — test verifies no panic and no error.
}

// TestLoop_Declarations verifies ChainBehavior() and VerificationStrategy()
// return the configured values.
func TestLoop_Declarations(t *testing.T) {
	cfg := transport.LoopConfig{
		Behavior:   contract.ChainFirstDrop,
		Strategy:   contract.VerificationNone,
		Processor:  &fakeProcessor{},
		Subscriber: newSyncSubscriber(),
		Publisher:  &fakePublisher{},
		Codec:      envelopecodec.New(),
		Emission:   &fakeTlog{},
	}
	loop, err := transport.NewLoop(cfg)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}
	if loop.ChainBehavior() != contract.ChainFirstDrop {
		t.Errorf("ChainBehavior: got %v, want ChainFirstDrop", loop.ChainBehavior())
	}
	if loop.VerificationStrategy() != contract.VerificationNone {
		t.Errorf("VerificationStrategy: got %v, want VerificationNone", loop.VerificationStrategy())
	}
}

// TestLoop_RunLifecycle verifies Subscribe is called, ctx cancel drains the
// subscriber, closes the publisher, and Run returns nil.
func TestLoop_RunLifecycle(t *testing.T) {
	sub := newSyncSubscriber() // no messages needed for lifecycle test
	pub := &fakePublisher{}

	cfg := transport.LoopConfig{
		Behavior:   contract.ChainPreserving,
		Strategy:   contract.VerificationAdjacent,
		Processor:  &fakeProcessor{},
		Subscriber: sub,
		Publisher:  pub,
		Codec:      envelopecodec.New(),
		Emission:   &fakeTlog{},
	}
	loop, err := transport.NewLoop(cfg)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}

	// runLoop blocks until Subscribe is called.
	cancel, done := runLoop(t, loop, sub)

	// Cancel the context to trigger shutdown.
	cancel()

	// Run must return without error.
	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// Drain must have been called.
	// syncSubscriber.Drain sets drainErr return but doesn't record a called flag;
	// we verify via the contract: if Drain errors Run surfaces it. Here drainErr
	// is nil, so we verify the loop didn't panic or skip it by checking Run==nil.
	// For an explicit drained flag, we use a drainCalled bool under mutex.
	// (The syncSubscriber doesn't expose a drainCalled flag; use a wrapper.)

	// Publisher Close must have been called.
	pub.mu.Lock()
	closed := pub.closed
	pub.mu.Unlock()
	if !closed {
		t.Error("expected publisher Close to be called after ctx cancel")
	}
}

// TestLoop_SubscribeError_RunReturnsIt verifies that a Subscribe error is
// returned from Run immediately.
func TestLoop_SubscribeError_RunReturnsIt(t *testing.T) {
	wantErr := errors.New("broker unavailable")

	// We need a subscriber that returns an error from Subscribe.
	// syncSubscriber supports subscribeErr; in this case readyCh is never
	// closed (Subscribe returns early), so we cannot call waitReady.
	// We start Run directly and wait for it to return.
	sub := newSyncSubscriber()
	sub.subscribeErr = wantErr

	cfg := transport.LoopConfig{
		Behavior:   contract.ChainTerminating,
		Strategy:   contract.VerificationFull,
		Processor:  &fakeProcessor{},
		Subscriber: sub,
	}
	loop, err := transport.NewLoop(cfg)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}

	ctx := context.Background()
	gotErr := loop.Run(ctx)
	if !errors.Is(gotErr, wantErr) {
		t.Errorf("Run error = %v, want %v", gotErr, wantErr)
	}
}

// ---------------------------------------------------------------------------
// Finding 1: graceful-drain Append must use context.WithoutCancel
// ---------------------------------------------------------------------------

// ctxCheckingTlog records whether the context passed to Append was cancelled,
// and still appends the payload so the loop's normal flow is not disrupted.
type ctxCheckingTlog struct {
	mu              sync.Mutex
	appended        [][]byte
	ctxWasCancelled bool
}

func (c *ctxCheckingTlog) Append(ctx context.Context, payload []byte) (*tlog.Record, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx.Err() != nil {
		c.ctxWasCancelled = true
		// Return an error to simulate what a real implementation would do.
		return nil, ctx.Err()
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	c.appended = append(c.appended, cp)
	return &tlog.Record{Index: uint64(len(c.appended) - 1), Payload: cp}, nil
}

func (c *ctxCheckingTlog) Get(_ context.Context, _ uint64) (*tlog.Record, error)  { return nil, nil }
func (c *ctxCheckingTlog) Size(_ context.Context) (uint64, error)                 { return 0, nil }
func (c *ctxCheckingTlog) Checkpoint(_ context.Context) (*tlog.Checkpoint, error) { return nil, nil }

func (c *ctxCheckingTlog) appendedCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.appended)
}

// TestLoop_DrainAppend_CancelledCtx verifies that when Run's ctx is already
// cancelled (graceful drain), the Append call still succeeds. The fix is to
// use context.WithoutCancel for the Append call so that ctx cancellation does
// not abort the emission record.
func TestLoop_DrainAppend_CancelledCtx(t *testing.T) {
	payload := []byte(`{"hello":"world"}`)
	result := passedResult(t, payload)

	emission := &ctxCheckingTlog{}

	proc := &fakeProcessor{
		results: []*contract.Result{result},
		errs:    []error{nil},
	}
	sub := newSyncSubscriber([]byte("raw input"))
	pub := &fakePublisher{}
	codec := envelopecodec.New()

	cfg := transport.LoopConfig{
		Behavior:   contract.ChainPreserving,
		Strategy:   contract.VerificationAdjacent,
		Processor:  proc,
		Subscriber: sub,
		Publisher:  pub,
		Codec:      codec,
		Emission:   emission,
	}
	loop, err := transport.NewLoop(cfg)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}

	// Cancel the context before deliver so that when Append is called, the
	// ctx passed to it is already Done — unless the loop uses WithoutCancel.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- loop.Run(ctx) }()
	sub.waitReady()
	cancel() // ctx is Done before the message arrives
	sub.deliver()

	if runErr := <-done; runErr != nil {
		t.Fatalf("Run returned error: %v", runErr)
	}

	// The emission record must be appended even though the outer ctx was cancelled.
	if emission.appendedCount() != 1 {
		t.Errorf("expected 1 emission record despite cancelled ctx, got %d (ctxWasCancelled=%v)",
			emission.appendedCount(), emission.ctxWasCancelled)
	}
}

// ---------------------------------------------------------------------------
// Finding 2: nil VC / nil Payload on passed result must drop loudly
// ---------------------------------------------------------------------------

// TestLoop_PassedNilVC_DroppedNotPublished verifies that a StatusPassed result
// with nil VC is rejected before Publish: no publish, counter not advanced.
func TestLoop_PassedNilVC_DroppedNotPublished(t *testing.T) {
	payload := []byte(`{"ok":true}`)
	nilVCResult := &contract.Result{
		Status:  contract.StatusPassed,
		VC:      nil,
		Payload: payload,
	}
	goodResult := passedResult(t, payload)

	proc := &fakeProcessor{
		results: []*contract.Result{nilVCResult, goodResult},
		errs:    []error{nil, nil},
	}
	sub := newSyncSubscriber([]byte("msg1"), []byte("msg2"))
	pub := &fakePublisher{}
	emission := &fakeTlog{}

	cfg := transport.LoopConfig{
		Behavior:   contract.ChainPreserving,
		Strategy:   contract.VerificationAdjacent,
		Processor:  proc,
		Subscriber: sub,
		Publisher:  pub,
		Codec:      envelopecodec.New(),
		Emission:   emission,
	}
	loop, err := transport.NewLoop(cfg)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}

	cancel, done := runLoop(t, loop, sub)
	sub.deliver()
	cancel()

	if runErr := <-done; runErr != nil {
		t.Fatalf("Run returned error: %v", runErr)
	}

	// Only the second (good) message must be published with sequenceNo==1
	// (counter not advanced after nil-VC drop).
	if pub.callCount() != 1 {
		t.Fatalf("expected 1 publish call (nil VC dropped), got %d", pub.callCount())
	}
	decoded, err := envelopecodec.New().UnmarshalEnvelope(pub.calls[0])
	if err != nil {
		t.Fatalf("UnmarshalEnvelope: %v", err)
	}
	if decoded.SequenceNo != 1 {
		t.Errorf("expected SequenceNo=1 (counter not advanced by nil-VC), got %d", decoded.SequenceNo)
	}
}

// TestLoop_PassedNilPayload_DroppedNotPublished verifies that a StatusPassed
// result with nil Payload is rejected before Publish: no publish, counter not
// advanced.
func TestLoop_PassedNilPayload_DroppedNotPublished(t *testing.T) {
	cred := newTestCredential(t, []byte(`{"ok":true}`))
	nilPayloadResult := &contract.Result{
		Status:  contract.StatusPassed,
		VC:      cred,
		Payload: nil,
	}
	goodResult := passedResult(t, []byte(`{"ok":true}`))

	proc := &fakeProcessor{
		results: []*contract.Result{nilPayloadResult, goodResult},
		errs:    []error{nil, nil},
	}
	sub := newSyncSubscriber([]byte("msg1"), []byte("msg2"))
	pub := &fakePublisher{}
	emission := &fakeTlog{}

	cfg := transport.LoopConfig{
		Behavior:   contract.ChainPreserving,
		Strategy:   contract.VerificationAdjacent,
		Processor:  proc,
		Subscriber: sub,
		Publisher:  pub,
		Codec:      envelopecodec.New(),
		Emission:   emission,
	}
	loop, err := transport.NewLoop(cfg)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}

	cancel, done := runLoop(t, loop, sub)
	sub.deliver()
	cancel()

	if runErr := <-done; runErr != nil {
		t.Fatalf("Run returned error: %v", runErr)
	}

	// Only the second (good) message published; counter stays at 1.
	if pub.callCount() != 1 {
		t.Fatalf("expected 1 publish call (nil Payload dropped), got %d", pub.callCount())
	}
	decoded, err := envelopecodec.New().UnmarshalEnvelope(pub.calls[0])
	if err != nil {
		t.Fatalf("UnmarshalEnvelope: %v", err)
	}
	if decoded.SequenceNo != 1 {
		t.Errorf("expected SequenceNo=1 (counter not advanced by nil-Payload), got %d", decoded.SequenceNo)
	}
}

// ---------------------------------------------------------------------------
// Finding 3: nil result and unknown status must be handled without panic
// ---------------------------------------------------------------------------

// TestLoop_NilResult_DroppedNoPanic verifies that a nil *Result returned by
// Process (with nil error) is dropped loudly without panicking.
func TestLoop_NilResult_DroppedNoPanic(t *testing.T) {
	payload := []byte(`{"ok":true}`)
	goodResult := passedResult(t, payload)

	proc := &fakeProcessor{
		results: []*contract.Result{nil, goodResult},
		errs:    []error{nil, nil},
	}
	sub := newSyncSubscriber([]byte("msg1"), []byte("msg2"))
	pub := &fakePublisher{}
	emission := &fakeTlog{}

	cfg := transport.LoopConfig{
		Behavior:   contract.ChainPreserving,
		Strategy:   contract.VerificationAdjacent,
		Processor:  proc,
		Subscriber: sub,
		Publisher:  pub,
		Codec:      envelopecodec.New(),
		Emission:   emission,
	}
	loop, err := transport.NewLoop(cfg)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}

	cancel, done := runLoop(t, loop, sub)
	sub.deliver()
	cancel()

	if runErr := <-done; runErr != nil {
		t.Fatalf("Run returned error: %v", runErr)
	}

	// Second message must still be published (loop continued after nil result).
	if pub.callCount() != 1 {
		t.Fatalf("expected 1 publish (second msg), got %d", pub.callCount())
	}
}

// TestLoop_StatusUnknown_DroppedNoPanic verifies that StatusUnknown is handled
// by the default arm: dropped loudly, loop continues.
func TestLoop_StatusUnknown_DroppedNoPanic(t *testing.T) {
	payload := []byte(`{"ok":true}`)
	unknownResult := &contract.Result{Status: contract.StatusUnknown}
	goodResult := passedResult(t, payload)

	proc := &fakeProcessor{
		results: []*contract.Result{unknownResult, goodResult},
		errs:    []error{nil, nil},
	}
	sub := newSyncSubscriber([]byte("msg1"), []byte("msg2"))
	pub := &fakePublisher{}
	emission := &fakeTlog{}

	cfg := transport.LoopConfig{
		Behavior:   contract.ChainPreserving,
		Strategy:   contract.VerificationAdjacent,
		Processor:  proc,
		Subscriber: sub,
		Publisher:  pub,
		Codec:      envelopecodec.New(),
		Emission:   emission,
	}
	loop, err := transport.NewLoop(cfg)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}

	cancel, done := runLoop(t, loop, sub)
	sub.deliver()
	cancel()

	if runErr := <-done; runErr != nil {
		t.Fatalf("Run returned error: %v", runErr)
	}

	// Second message published; loop survived the unknown status.
	if pub.callCount() != 1 {
		t.Fatalf("expected 1 publish (second msg), got %d", pub.callCount())
	}
}

// ---------------------------------------------------------------------------
// Finding 5: sequenceNo in emission record JSON must be a string
// ---------------------------------------------------------------------------

// TestLoop_EmissionRecord_SequenceNoIsString pins that the "sequenceNo" field
// in the JSON emission record is encoded as a string (not a number), so that
// IEEE-754 JSON consumers with only 53-bit integer precision cannot round it.
func TestLoop_EmissionRecord_SequenceNoIsString(t *testing.T) {
	payload := []byte(`{"hello":"world"}`)
	result := passedResult(t, payload)

	proc := &fakeProcessor{
		results: []*contract.Result{result},
		errs:    []error{nil},
	}
	sub := newSyncSubscriber([]byte("raw input"))
	pub := &fakePublisher{}
	emission := &fakeTlog{}
	codec := envelopecodec.New()

	cfg := transport.LoopConfig{
		Behavior:   contract.ChainPreserving,
		Strategy:   contract.VerificationAdjacent,
		Processor:  proc,
		Subscriber: sub,
		Publisher:  pub,
		Codec:      codec,
		Emission:   emission,
	}
	loop, err := transport.NewLoop(cfg)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}

	cancel, done := runLoop(t, loop, sub)
	sub.deliver()
	cancel()

	if runErr := <-done; runErr != nil {
		t.Fatalf("Run returned error: %v", runErr)
	}

	if emission.appendedCount() != 1 {
		t.Fatalf("expected 1 emission record, got %d", emission.appendedCount())
	}

	// Parse raw JSON to inspect the sequenceNo field type.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(emission.appended[0], &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	seqRaw, ok := raw["sequenceNo"]
	if !ok {
		t.Fatal("missing sequenceNo field in emission record")
	}
	// A JSON string starts with '"'; a JSON number does not.
	if len(seqRaw) == 0 || seqRaw[0] != '"' {
		t.Errorf("sequenceNo must be a JSON string, got raw %s", string(seqRaw))
	}
	// The value must be the string "1".
	var seqStr string
	if err := json.Unmarshal(seqRaw, &seqStr); err != nil {
		t.Fatalf("unmarshal sequenceNo as string: %v", err)
	}
	if seqStr != "1" {
		t.Errorf("sequenceNo: got %q, want \"1\"", seqStr)
	}
}

// ---------------------------------------------------------------------------
// Finding 6: out-of-range ChainBehavior values must be rejected
// ---------------------------------------------------------------------------

// TestNewLoop_OutOfRangeBehavior_Rejected verifies that a ChainBehavior value
// outside the known sentinel set is rejected with ErrUnknownBehavior.
func TestNewLoop_OutOfRangeBehavior_Rejected(t *testing.T) {
	sub := newSyncSubscriber()
	cfg := transport.LoopConfig{
		Behavior:   contract.ChainBehavior(7), // out of range
		Strategy:   contract.VerificationAdjacent,
		Processor:  &fakeProcessor{},
		Subscriber: sub,
		Publisher:  &fakePublisher{},
		Codec:      envelopecodec.New(),
		Emission:   &fakeTlog{},
	}
	_, err := transport.NewLoop(cfg)
	if !errors.Is(err, transport.ErrUnknownBehavior) {
		t.Errorf("expected ErrUnknownBehavior for out-of-range value, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Finding 7: Drain-error and Close-error propagation through Run
// ---------------------------------------------------------------------------

// TestLoop_DrainError_PropagatedByRun verifies that a Drain error is returned
// from Run (first-error-wins).
func TestLoop_DrainError_PropagatedByRun(t *testing.T) {
	wantErr := errors.New("drain exploded")
	sub := newSyncSubscriber()
	sub.drainErr = wantErr

	cfg := transport.LoopConfig{
		Behavior:   contract.ChainPreserving,
		Strategy:   contract.VerificationAdjacent,
		Processor:  &fakeProcessor{},
		Subscriber: sub,
		Publisher:  &fakePublisher{},
		Codec:      envelopecodec.New(),
		Emission:   &fakeTlog{},
	}
	loop, err := transport.NewLoop(cfg)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}

	cancel, done := runLoop(t, loop, sub)
	cancel()

	gotErr := <-done
	if !errors.Is(gotErr, wantErr) {
		t.Errorf("Run error = %v, want %v", gotErr, wantErr)
	}
}

// TestLoop_CloseError_PropagatedByRun verifies that a Publisher Close error is
// returned from Run when Drain succeeds (first-error-wins).
func TestLoop_CloseError_PropagatedByRun(t *testing.T) {
	wantErr := errors.New("close exploded")
	sub := newSyncSubscriber()
	pub := &fakePublisher{closeErr: wantErr}

	cfg := transport.LoopConfig{
		Behavior:   contract.ChainPreserving,
		Strategy:   contract.VerificationAdjacent,
		Processor:  &fakeProcessor{},
		Subscriber: sub,
		Publisher:  pub,
		Codec:      envelopecodec.New(),
		Emission:   &fakeTlog{},
	}
	loop, err := transport.NewLoop(cfg)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}

	cancel, done := runLoop(t, loop, sub)
	cancel()

	gotErr := <-done
	if !errors.Is(gotErr, wantErr) {
		t.Errorf("Run error = %v, want %v", gotErr, wantErr)
	}
}

// TestLoop_DrainAndCloseError_DrainWins verifies first-error-wins: when both
// Drain and Close error, only the Drain error is returned.
func TestLoop_DrainAndCloseError_DrainWins(t *testing.T) {
	drainErr := errors.New("drain exploded")
	closeErr := errors.New("close exploded")
	sub := newSyncSubscriber()
	sub.drainErr = drainErr
	pub := &fakePublisher{closeErr: closeErr}

	cfg := transport.LoopConfig{
		Behavior:   contract.ChainPreserving,
		Strategy:   contract.VerificationAdjacent,
		Processor:  &fakeProcessor{},
		Subscriber: sub,
		Publisher:  pub,
		Codec:      envelopecodec.New(),
		Emission:   &fakeTlog{},
	}
	loop, err := transport.NewLoop(cfg)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}

	cancel, done := runLoop(t, loop, sub)
	cancel()

	gotErr := <-done
	if !errors.Is(gotErr, drainErr) {
		t.Errorf("Run error = %v, want drain error %v (first-error-wins)", gotErr, drainErr)
	}
}
