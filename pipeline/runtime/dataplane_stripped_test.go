package runtime

import (
	"context"
	"testing"
	"time"

	natstransport "github.com/provin-line/oss/pipeline/transport/nats"
)

// fakePayloadStore is a minimal PayloadRetainStore stub — strippedPublisherFor
// only checks whether pw.store is nil, so a trivial stub suffices.
type fakePayloadStore struct{}

func (fakePayloadStore) Store(context.Context, []byte, string) (string, error) { return "", nil }

// Boot test (W3): serving NOT configured (PayloadStore nil) → the stripped
// publisher is nil, regardless of conn. It must not even dereference conn.
func TestStrippedPublisherFor_NilWhenNotServing(t *testing.T) {
	pw := payloadWiring{}
	if got := pw.strippedPublisherFor(nil, dpPipelineDID); got != nil {
		t.Errorf("strippedPublisherFor = %v, want nil (no PayloadStore configured)", got)
	}
}

// Boot test (W3): serving configured (PayloadStore non-nil) → a producing
// loop's stripped publisher is bound to "byref."+subject on the shared conn.
func TestStrippedPublisherFor_BoundToByReferenceSubject(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	conn, err := natstransport.Connect(context.Background(), natstransport.Config{URL: url, AccountSeed: accSeed})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	pw := payloadWiring{store: fakePayloadStore{}}
	pub := pw.strippedPublisherFor(conn, dpPipelineDID)
	if pub == nil {
		t.Fatal("strippedPublisherFor = nil, want a bound Publisher (PayloadStore configured)")
	}

	obs, err := natstransport.Connect(context.Background(), natstransport.Config{URL: url, AccountSeed: accSeed})
	if err != nil {
		t.Fatalf("observer connect: %v", err)
	}
	defer obs.Close()
	got := make(chan []byte, 4)
	const wantSubject = "byref." + dpPipelineDID
	if err := obs.Subscriber(wantSubject).Subscribe(func(b []byte) { got <- b }); err != nil {
		t.Fatalf("observer subscribe: %v", err)
	}

	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	_ = pub.Publish([]byte("probe"))
	for {
		select {
		case b := <-got:
			if string(b) != "probe" {
				t.Fatalf("payload = %q, want %q", b, "probe")
			}
			return
		case <-tick.C:
			_ = pub.Publish([]byte("probe"))
		case <-deadline:
			t.Fatalf("no message observed on %q — strippedPublisherFor did not bind to the byref-prefixed subject", wantSubject)
		}
	}
}
