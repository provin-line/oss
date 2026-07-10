package transport_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/provin-line/oss/pipeline/transport"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
)

// fakeRetainer records payloads it is asked to retain and whether a publish had
// already happened at retain time (to pin retain-before-publish ordering).
type fakeRetainer struct {
	pub                  *fakePublisher
	calls                [][]byte
	err                  error  // when set, Retain fails
	forceHash            string // when set, Retain returns this instead of the real hash
	retainedAfterPublish bool
}

func (r *fakeRetainer) Retain(_ context.Context, payload []byte) (string, error) {
	if r.pub != nil && r.pub.callCount() > 0 {
		r.retainedAfterPublish = true
	}
	buf := make([]byte, len(payload))
	copy(buf, payload)
	r.calls = append(r.calls, buf)
	if r.err != nil {
		return "", r.err
	}
	if r.forceHash != "" {
		return r.forceHash, nil
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// A retainer-equipped Emitter retains each payload BEFORE publishing, and the
// retained bytes are exactly the emitted payload.
func TestEmitter_Retain_BeforePublish(t *testing.T) {
	pub := &fakePublisher{}
	ret := &fakeRetainer{pub: pub}
	e, err := transport.NewEmitter(context.Background(), pub, envelopecodec.New(), &fakeTlog{}, nil, transport.WithPayloadRetainer(ret))
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	payload := []byte(`{"a":1}`)
	cred := newTestCredential(t, payload)
	if err := e.Emit(context.Background(), cred, payload); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if len(ret.calls) != 1 || string(ret.calls[0]) != string(payload) {
		t.Fatalf("retained = %v, want one call with the emitted payload", ret.calls)
	}
	if ret.retainedAfterPublish {
		t.Error("retain happened AFTER publish; want retain BEFORE publish")
	}
	if pub.callCount() != 1 {
		t.Errorf("publishes = %d, want 1", pub.callCount())
	}
}

// A retain error fails the emit BEFORE any publish, and the sequence is not
// advanced (the next attempt reuses sequence 1).
func TestEmitter_Retain_FailClosed(t *testing.T) {
	pub := &fakePublisher{}
	ret := &fakeRetainer{pub: pub, err: errors.New("store down")}
	e, err := transport.NewEmitter(context.Background(), pub, envelopecodec.New(), &fakeTlog{}, nil, transport.WithPayloadRetainer(ret))
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	payload := []byte(`{"a":1}`)
	cred := newTestCredential(t, payload)
	if err := e.Emit(context.Background(), cred, payload); err == nil {
		t.Fatal("Emit with retain failure: want error")
	}
	if pub.callCount() != 0 {
		t.Errorf("publishes = %d, want 0 (fail-closed before publish)", pub.callCount())
	}
	// Recover the retainer and confirm the sequence was not advanced: a
	// subsequent successful emit still uses sequence 1.
	ret.err = nil
	if err := e.Emit(context.Background(), cred, payload); err != nil {
		t.Fatalf("Emit after recovery: %v", err)
	}
	if got := seqOf(t, pub.calls[0]); got != 1 {
		t.Errorf("first delivered SequenceNo = %d, want 1 (number reused after retain failure)", got)
	}
}

// The emit-side binding gate: a retained payload whose content address differs
// from the credential's declared outputHash fails the emit (a producing-process
// bug — mismatched bytes paired with a credential).
func TestEmitter_Retain_BindingGate(t *testing.T) {
	pub := &fakePublisher{}
	// forceHash simulates a store returning an address that does not match the
	// credential's outputHash (equivalently, emitting bytes the credential does
	// not describe).
	ret := &fakeRetainer{pub: pub, forceHash: "sha256:" + hex.EncodeToString(make([]byte, 32))}
	e, err := transport.NewEmitter(context.Background(), pub, envelopecodec.New(), &fakeTlog{}, nil, transport.WithPayloadRetainer(ret))
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	payload := []byte(`{"a":1}`)
	cred := newTestCredential(t, payload)
	if err := e.Emit(context.Background(), cred, payload); err == nil {
		t.Fatal("Emit with binding mismatch: want error")
	}
	if pub.callCount() != 0 {
		t.Errorf("publishes = %d, want 0 (binding gate fails before publish)", pub.callCount())
	}
}

// Without a retainer the Emitter is an ordinary inline producer (no retain,
// publish as before).
func TestEmitter_NoRetainer_Unchanged(t *testing.T) {
	pub := &fakePublisher{}
	e, err := transport.NewEmitter(context.Background(), pub, envelopecodec.New(), &fakeTlog{}, nil)
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	payload := []byte(`{"a":1}`)
	if err := e.Emit(context.Background(), newTestCredential(t, payload), payload); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if pub.callCount() != 1 {
		t.Errorf("publishes = %d, want 1", pub.callCount())
	}
}
