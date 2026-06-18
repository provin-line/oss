package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/pipeline/chained"
	jsonataconv "github.com/provin-line/oss/pipeline/chained/converter/jsonata"
	"github.com/provin-line/oss/pipeline/chained/filter"
	jsonatafilter "github.com/provin-line/oss/pipeline/chained/filter/jsonata"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/provenance"
	"github.com/provin-line/oss/pipeline/provenance/vcdid"
	"github.com/provin-line/oss/pipeline/sink"
	"github.com/provin-line/oss/pipeline/source/ingest"
	"github.com/provin-line/oss/pipeline/transport"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	natstransport "github.com/provin-line/oss/pipeline/transport/nats"
	"github.com/provin-line/oss/resolver"
	"github.com/provin-line/oss/tlog/memlog"
	"github.com/provin-line/oss/vc"
)

// dataPlaneDeps are the cross-plane dependencies a data plane needs beyond its own
// keystore: the shared DID resolver (sink loops verify upstream credentials through it)
// and the sink Writer (where a sink delivers consumed events). They are zero for a
// source-only node — a source loop uses neither.
type dataPlaneDeps struct {
	Resolver   resolver.Resolver
	SinkWriter sink.Writer
}

// dataPlane is the node's set of running pipeline loops over one shared nats
// connection. It owns the connection's lifecycle: Run starts the loops, waits for
// them to drain on context cancellation, then closes the shared connection (the 17a
// Conn-owns-teardown contract realized at node level).
type dataPlane struct {
	conn  *natstransport.Conn // nil when there are zero loops
	loops []*transport.Loop
}

// buildDataPlane assembles the node's pipeline loops from the pipeline config. When
// no loops are configured it returns a no-op runner WITHOUT dialing nats, so an
// empty/absent pipeline config never requires a live broker (it does not regress the
// HTTP-only deployment). Otherwise it dials once as the node account and builds one
// loop per config entry over that shared connection, dispatching on role: a source
// loop signs FirstDrop credentials with keyStore; a sink loop verifies upstream
// credentials through deps.Resolver and writes consumed events to deps.SinkWriter.
func buildDataPlane(chainCfg *chainconfig.Config, pipeCfg *pipelineconfig.Config, keyStore keystore.KeyStore, deps dataPlaneDeps) (*dataPlane, error) {
	if len(pipeCfg.Loops) == 0 {
		return &dataPlane{}, nil
	}
	if chainCfg.Transport != chainconfig.TransportNATS {
		return nil, fmt.Errorf("standalone: data-plane loops require the nats transport, got %q", chainCfg.Transport)
	}

	conn, err := natstransport.Connect(natstransport.Config{
		URL:         chainCfg.NATS.URL,
		AccountSeed: chainCfg.NATS.AccountSeed,
	})
	if err != nil {
		return nil, fmt.Errorf("standalone: data-plane nats connect: %w", err)
	}

	dp := &dataPlane{conn: conn}
	builder := vc.NewBuilder(ed25519.NewSigner(keyStore))
	// Consuming loops (sink, chained) share one verifier (over the node's resolver) and one
	// in-memory ingress store, built lazily on the first such loop so a source-only node
	// needs no resolver. ensureConsumer builds them once and fails closed without a resolver.
	var verifier provenance.Verifier
	var ingressStore contract.IngressVCStore
	ensureConsumer := func(loopName string) error {
		if verifier != nil {
			return nil
		}
		if deps.Resolver == nil {
			return fmt.Errorf("standalone: loop %q: %s role requires a DID resolver", loopName, "consuming")
		}
		verifier = vc.NewVerifier(deps.Resolver, ed25519.Verifier{})
		ingressStore = newMemIngressStore()
		return nil
	}
	for _, lc := range pipeCfg.Loops {
		var loop *transport.Loop
		switch lc.Role {
		case pipelineconfig.RoleSource:
			loop, err = buildSourceLoop(conn, builder, lc)
		case pipelineconfig.RoleSink:
			if deps.SinkWriter == nil {
				_ = conn.Close()
				return nil, fmt.Errorf("standalone: loop %q: sink role requires a sink writer", lc.Name)
			}
			if err = ensureConsumer(lc.Name); err == nil {
				loop, err = buildSinkLoop(conn, verifier, ingressStore, deps.SinkWriter, lc)
			}
		case pipelineconfig.RoleChained:
			if err = ensureConsumer(lc.Name); err == nil {
				loop, err = buildChainedLoop(conn, builder, verifier, ingressStore, lc)
			}
		default:
			// The config layer fails closed on unknown/unsupported roles; this guards the
			// assembly seam against a role string that bypassed validation.
			_ = conn.Close()
			return nil, fmt.Errorf("standalone: loop %q: unsupported role %q", lc.Name, lc.Role)
		}
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		dp.loops = append(dp.loops, loop)
	}
	return dp, nil
}

// buildSourceLoop assembles one source (FirstDrop) loop: ingress Subscriber → ingest
// processor (vcdid signer over the keystore) → output Publisher, with a memlog
// emission log. The config layer has already validated that lc.Role is source.
func buildSourceLoop(conn *natstransport.Conn, builder *vc.Builder, lc pipelineconfig.LoopConfig) (*transport.Loop, error) {
	src := lc.Source
	signer, err := vcdid.NewSigner(vcdid.Config{
		Builder:             builder,
		IssuerDID:           src.Issuer.DID,
		KeyID:               src.Issuer.KeyID,
		VerificationMethod:  src.Issuer.VerificationMethod,
		PipelineID:          src.PipelineID,
		ProcessID:           src.ProcessID,
		TransformationClaim: src.TransformationClaim,
	})
	if err != nil {
		return nil, fmt.Errorf("standalone: loop %q: source signer: %w", lc.Name, err)
	}
	proc, err := ingest.New(ingest.Config{Signer: signer})
	if err != nil {
		return nil, fmt.Errorf("standalone: loop %q: ingest processor: %w", lc.Name, err)
	}
	loop, err := transport.NewLoop(transport.LoopConfig{
		Behavior:   contract.ChainFirstDrop,
		Strategy:   contract.VerificationNone,
		Processor:  proc,
		Subscriber: conn.Subscriber(lc.IngressSubject),
		Publisher:  conn.Publisher(src.OutputSubject),
		Codec:      envelopecodec.New(),
		Emission:   memlog.New(),
	})
	if err != nil {
		return nil, fmt.Errorf("standalone: loop %q: build loop: %w", lc.Name, err)
	}
	return loop, nil
}

// buildSinkLoop assembles one terminating sink loop: ingress Subscriber → sink
// processor (verify the upstream credential, enforce payload binding, write
// out-of-network) with NO Publisher/Codec/Emission (the ChainTerminating contract — the
// sink processor holds its own Codec). The config layer has validated lc.Sink.
func buildSinkLoop(conn *natstransport.Conn, verifier provenance.Verifier, store contract.IngressVCStore, writer sink.Writer, lc pipelineconfig.LoopConfig) (*transport.Loop, error) {
	strategy, err := verificationStrategy(lc.Sink.VerificationStrategy)
	if err != nil {
		return nil, fmt.Errorf("standalone: loop %q: %w", lc.Name, err)
	}
	kind, err := sinkKind(lc.Sink.Kind)
	if err != nil {
		return nil, fmt.Errorf("standalone: loop %q: %w", lc.Name, err)
	}
	proc, err := sink.New(sink.Config{
		Strategy:         strategy,
		Kind:             kind,
		Codec:            envelopecodec.New(),
		Verifier:         verifier,
		Store:            store,
		Writer:           writer,
		UpstreamEndpoint: lc.Sink.UpstreamEndpoint,
	})
	if err != nil {
		return nil, fmt.Errorf("standalone: loop %q: sink processor: %w", lc.Name, err)
	}
	loop, err := transport.NewLoop(transport.LoopConfig{
		Behavior:   contract.ChainTerminating,
		Strategy:   strategy,
		Processor:  proc,
		Subscriber: conn.Subscriber(lc.IngressSubject),
		// A terminating sink has no Publisher/Codec/Emission (NewLoop enforces this).
	})
	if err != nil {
		return nil, fmt.Errorf("standalone: loop %q: build loop: %w", lc.Name, err)
	}
	return loop, nil
}

// buildChainedLoop assembles one chained (relay) loop: ingress Subscriber → chained
// processor (verify the upstream credential, enforce payload binding, optionally
// filter/convert, re-sign a ChainPreserving credential linking the predecessor) → output
// Publisher, with a memlog emission log. It both consumes (verifier + store) and produces
// (signer + Publisher + Codec + Emission). The config layer has validated lc.Chained.
func buildChainedLoop(conn *natstransport.Conn, builder *vc.Builder, verifier provenance.Verifier, store contract.IngressVCStore, lc pipelineconfig.LoopConfig) (*transport.Loop, error) {
	cc := lc.Chained
	signer, err := vcdid.NewSigner(vcdid.Config{
		Builder:             builder,
		IssuerDID:           cc.Issuer.DID,
		KeyID:               cc.Issuer.KeyID,
		VerificationMethod:  cc.Issuer.VerificationMethod,
		PipelineID:          cc.PipelineID,
		ProcessID:           cc.ProcessID,
		TransformationClaim: cc.TransformationClaim,
	})
	if err != nil {
		return nil, fmt.Errorf("standalone: loop %q: chained signer: %w", lc.Name, err)
	}
	strategy, err := verificationStrategy(cc.VerificationStrategy)
	if err != nil {
		return nil, fmt.Errorf("standalone: loop %q: %w", lc.Name, err)
	}
	chainedCfg := chained.Config{
		Strategy:          strategy,
		IngressConformant: true,
		UpstreamEndpoint:  cc.UpstreamEndpoint,
		Codec:             envelopecodec.New(),
		Verifier:          verifier,
		Store:             store,
		Signer:            signer,
	}
	// Converter/filters compile at boot — a malformed JSONata expression fails closed here.
	if cc.Converter != "" {
		conv, err := jsonataconv.New(cc.Converter)
		if err != nil {
			return nil, fmt.Errorf("standalone: loop %q: converter: %w", lc.Name, err)
		}
		chainedCfg.Converter = conv
	}
	if len(cc.Filters) > 0 {
		filt, err := jsonatafilter.New(cc.Filters)
		if err != nil {
			return nil, fmt.Errorf("standalone: loop %q: filters: %w", lc.Name, err)
		}
		chainedCfg.Filters = []filter.Filter{filt}
	}
	proc, err := chained.New(chainedCfg)
	if err != nil {
		return nil, fmt.Errorf("standalone: loop %q: chained processor: %w", lc.Name, err)
	}
	loop, err := transport.NewLoop(transport.LoopConfig{
		Behavior:   contract.ChainPreserving,
		Strategy:   strategy,
		Processor:  proc,
		Subscriber: conn.Subscriber(lc.IngressSubject),
		Publisher:  conn.Publisher(cc.OutputSubject),
		Codec:      envelopecodec.New(),
		Emission:   memlog.New(),
	})
	if err != nil {
		return nil, fmt.Errorf("standalone: loop %q: build loop: %w", lc.Name, err)
	}
	return loop, nil
}

// verificationStrategy maps a (config-validated) strategy token to its contract value.
// slice-17c admits "adjacent" only; "full" is rejected at config load.
func verificationStrategy(s string) (contract.VerificationStrategy, error) {
	switch s {
	case pipelineconfig.StrategyAdjacent:
		return contract.VerificationAdjacent, nil
	case pipelineconfig.StrategyFull:
		return contract.VerificationUnknown, fmt.Errorf("verification-strategy %q is unsupported in slice-17c", s)
	default:
		return contract.VerificationUnknown, fmt.Errorf("unknown verification-strategy %q", s)
	}
}

// sinkKind maps a (config-validated) sink-kind token to its contract value.
func sinkKind(k string) (contract.SinkKind, error) {
	switch k {
	case pipelineconfig.SinkObservationOnly:
		return contract.SinkObservationOnly, nil
	case pipelineconfig.SinkProduction:
		return contract.SinkProduction, nil
	case pipelineconfig.SinkArchival:
		return contract.SinkArchival, nil
	default:
		return contract.SinkKindUnknown, fmt.Errorf("unknown sink.kind %q", k)
	}
}

// memIngressStore is the PoC in-memory ingress-VC store (parity with the memlog emission
// log): it retains verified ingress credentials in memory. A durable store lands later.
type memIngressStore struct {
	mu  sync.Mutex
	vcs []*vc.PipelinePassCredential
}

func newMemIngressStore() *memIngressStore { return &memIngressStore{} }

func (s *memIngressStore) StoreIngressVC(_ context.Context, cred *vc.PipelinePassCredential, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vcs = append(s.vcs, cred)
	return nil
}

// Run runs every loop until ctx is cancelled, waits for all of them to drain and
// return, then closes the shared connection. A zero-loop runner returns immediately.
// It returns the first loop error, or the connection close error if the loops were
// clean.
//
// Loops share a child context derived from ctx, so the first loop to fail (e.g. a
// boot-time Subscribe error) cancels its siblings and Run returns promptly — it does
// not block until an external cancellation arrives.
func (d *dataPlane) Run(ctx context.Context) error {
	if len(d.loops) == 0 {
		return nil
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	errs := make(chan error, len(d.loops))
	for _, l := range d.loops {
		wg.Add(1)
		go func(l *transport.Loop) {
			defer wg.Done()
			if err := l.Run(runCtx); err != nil {
				errs <- err
				cancel() // a loop failed: drain the siblings instead of blocking on them
			}
		}(l)
	}
	wg.Wait()
	close(errs)

	// All loops have drained (Subscriber.Drain + Publisher.Close); only now tear the
	// shared connection down.
	closeErr := d.conn.Close()

	for err := range errs {
		if err != nil {
			return err
		}
	}
	return closeErr
}
