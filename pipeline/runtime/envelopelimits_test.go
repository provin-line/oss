package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/gen/go/dplaax/pipeline/v1"
	"github.com/provin-line/oss/pipeline/sink"
	"github.com/provin-line/oss/pipeline/sink/console"
	"github.com/provin-line/oss/pipeline/source/ingest"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	natstransport "github.com/provin-line/oss/pipeline/transport/nats"
	"github.com/provin-line/oss/tlog"
	"google.golang.org/protobuf/proto"
)

// Build refuses limits the codec refuses, before it dials: the address here
// is never reached.
func TestBuildRefusesInvalidEnvelopeLimits(t *testing.T) {
	cases := map[string][2]int{
		"neither set":             {0, 0},
		"no credential bound":     {0, 1 << 20},
		"no inline payload bound": {1 << 20, 0},
		"negative":                {-1, 1 << 20},
		"overflowing":             {math.MaxInt, 1},
	}
	for name, l := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := dpPipelineCfg()
			cfg.NATS = NATSConfig{URL: "nats://192.0.2.1:4222", AccountSeed: "bogus"}
			cfg.MaxCredentialSize, cfg.MaxInlinePayloadSize = l[0], l[1]
			_, err := Build(context.Background(), cfg, dpKeyStore(t), Deps{})
			if !errors.Is(err, envelopecodec.ErrInvalidLimits) {
				t.Fatalf("got %v, want ErrInvalidLimits", err)
			}
		})
	}
}

// A consuming loop decodes with the limits Build was given: an archival sink
// whose inline payload bound is 8 bytes records an envelope carrying 9 as a
// decode failure, naming the two sizes.
func TestDataPlane_SinkRefusesAnInlinePayloadPastTheBound(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	cfg := withNATS(url, accSeed, dpArchivalSinkCfg())
	cfg.MaxInlinePayloadSize = 8
	cfg.RejectLogDir = t.TempDir()
	dp, err := Build(context.Background(), cfg, dpArchiveKeyStore(t, dpArchiveReceiptIssr), Deps{
		Resolver:   stubResolver{},
		SinkWriter: console.New(io.Discard),
		VCStore:    dpVCStore(),
		AuditQueue: newMemAuditQueue(),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(func() { _ = dp.Close() })
	rejects, ok := dp.tlogClosers[0].(tlog.Log)
	if !ok {
		t.Fatalf("tlogClosers[0] = %T, want the reject log", dp.tlogClosers[0])
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- dp.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-runDone:
		case <-time.After(5 * time.Second):
			t.Error("dp.Run did not return after context cancel")
		}
	})

	pub, err := natstransport.Connect(context.Background(), natstransport.Config{URL: url, AccountSeed: accSeed})
	if err != nil {
		t.Fatalf("publisher connect: %v", err)
	}
	t.Cleanup(func() { _ = pub.Close() })
	wire, err := proto.Marshal(&pipeline.Envelope{Credential: []byte(`{}`), Payload: []byte("ZZZZZZZZZ"), SequenceNo: 1})
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	p := pub.Publisher(dpPipelineDID)

	// Publish until the sink has subscribed and recorded a reject.
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		_ = p.Publish(wire)
		size, err := rejects.Size(context.Background())
		if err != nil {
			t.Fatalf("reject log size: %v", err)
		}
		if size > 0 {
			break
		}
		select {
		case <-tick.C:
		case <-deadline:
			t.Fatal("no reject recorded")
		}
	}
	rec, err := rejects.Get(context.Background(), 0)
	if err != nil {
		t.Fatalf("reject log get: %v", err)
	}
	var got sink.RejectRecord
	if err := json.Unmarshal(rec.Payload, &got); err != nil {
		t.Fatalf("decode reject record: %v", err)
	}
	if got.Reason != sink.RejectDecodeFailure {
		t.Errorf("reason: got %q, want %q", got.Reason, sink.RejectDecodeFailure)
	}
	if !strings.Contains(got.Detail, "inline payload too large: 9 bytes, beyond the bound of 8") {
		t.Errorf("detail %q does not name the inline payload's size and bound", got.Detail)
	}
	if strings.Contains(got.Detail, "ZZZ") {
		t.Errorf("detail %q quotes the payload", got.Detail)
	}
}

// A source loop refuses a raw input longer than MaxIngestPayloadSize before it
// reads it, and its sequence does not advance for one. Once an input within
// the bound has come out as number 1 (the loop is subscribed), an input past
// the bound and then one within it are sent in that order: the next envelope
// carries the second and follows the last number.
func TestDataPlane_SourceRefusesAnInputPastMaxIngestPayloadSize(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	const first, past, second = `{"a":1}`, `{"a":12}`, `{"b":2}`
	cfg := withNATS(url, accSeed, dpPipelineCfg())
	cfg.MaxIngestPayloadSize = len(first)
	dp, err := Build(context.Background(), cfg, dpKeyStore(t), Deps{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(func() { _ = dp.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- dp.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-runDone:
		case <-time.After(5 * time.Second):
			t.Error("dp.Run did not return after context cancel")
		}
	})

	obs, err := natstransport.Connect(context.Background(), natstransport.Config{URL: url, AccountSeed: accSeed})
	if err != nil {
		t.Fatalf("observer connect: %v", err)
	}
	t.Cleanup(func() { _ = obs.Close() })
	got := make(chan []byte, 16)
	if err := obs.Subscriber(dpPipelineDID).Subscribe(func(b []byte) { got <- b }); err != nil {
		t.Fatalf("observer subscribe: %v", err)
	}
	injector := obs.Publisher(dpIngress)
	decode := func(wire []byte) (string, uint64) {
		t.Helper()
		env, err := testCodec().UnmarshalEnvelope(wire)
		if err != nil {
			t.Fatalf("decode envelope: %v", err)
		}
		return string(env.Payload), env.SequenceNo
	}

	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
subscribed:
	for {
		_ = injector.Publish([]byte(first))
		select {
		case wire := <-got:
			if payload, seq := decode(wire); payload != first || seq != 1 {
				t.Fatalf("first envelope: %q number %d, want %q number 1", payload, seq, first)
			}
			break subscribed
		case <-tick.C:
		case <-deadline:
			t.Fatal("no envelope delivered on the output subject")
		}
	}

	if err := injector.Publish([]byte(past)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := injector.Publish([]byte(second)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	// A retried first input may still come out first; it is skipped, and the
	// next envelope must follow its number.
	last := uint64(1)
	for {
		select {
		case wire := <-got:
			payload, seq := decode(wire)
			if payload == first {
				last = seq
				continue
			}
			if payload != second || seq != last+1 {
				t.Errorf("next envelope: %q number %d, want %q number %d", payload, seq, second, last+1)
			}
			return
		case <-time.After(5 * time.Second):
			t.Fatal("no envelope after the input past the bound")
		}
	}
}

// A source loop needs MaxIngestPayloadSize, which bounds its raw input and
// its push route alike: Build refuses one that is not positive before it
// dials (the address here is never reached).
func TestBuildRefusesASourceLoopWithoutMaxIngestPayloadSize(t *testing.T) {
	for _, n := range []int{0, -1} {
		cfg := dpPipelineCfg()
		cfg.NATS = NATSConfig{URL: "nats://192.0.2.1:4222", AccountSeed: "bogus"}
		cfg.MaxIngestPayloadSize = n
		_, err := Build(context.Background(), cfg, dpKeyStore(t), Deps{})
		if !errors.Is(err, ingest.ErrInvalidMaxPayloadSize) {
			t.Errorf("MaxIngestPayloadSize %d: got %v, want ingest.ErrInvalidMaxPayloadSize", n, err)
		}
	}
}

// Every push binding belongs to a source loop, so a node with no source loop
// has none and does not read MaxIngestPayloadSize; a node with no loop at
// all reads none of the limits.
func TestBuildReadsMaxIngestPayloadSizeOnlyForSourceLoops(t *testing.T) {
	zero, err := Build(context.Background(), &Config{}, dpKeyStore(t), Deps{})
	if err != nil {
		t.Fatalf("Build with no loop: %v", err)
	}
	if len(zero.PushBindings()) != 0 {
		t.Errorf("no loop: %d push bindings", len(zero.PushBindings()))
	}

	url, accSeed := dpAccountServer(t)
	cfg := withNATS(url, accSeed, dpSinkCfg())
	cfg.MaxIngestPayloadSize = 0
	dp, err := Build(context.Background(), cfg, dpKeyStore(t), Deps{
		Resolver:   stubResolver{},
		SinkWriter: console.New(io.Discard),
		VCStore:    dpVCStore(),
		AuditQueue: newMemAuditQueue(),
	})
	if err != nil {
		t.Fatalf("Build with a sink loop only: %v", err)
	}
	t.Cleanup(func() { _ = dp.Close() })
	if len(dp.PushBindings()) != 0 {
		t.Errorf("sink only: %d push bindings", len(dp.PushBindings()))
	}
}

// A push-enabled source loop's binding carries the bound its loop applies.
func TestBuildGivesAPushBindingTheIngestBound(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	cfg := withNATS(url, accSeed, dpPipelineCfg())
	cfg.Loops[0].Source.PushIngress = true
	cfg.MaxIngestPayloadSize = 4096
	dp, err := Build(context.Background(), cfg, dpKeyStore(t), Deps{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(func() { _ = dp.Close() })
	bindings := dp.PushBindings()
	if len(bindings) != 1 || bindings[0].MaxBodySize != 4096 {
		t.Fatalf("push bindings = %+v, want one with MaxBodySize 4096", bindings)
	}
}
