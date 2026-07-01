package main

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/gen/go/dplaax/vc/v1/vcpbconnect"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	vcresolverclient "github.com/provin-line/oss/network/pkg/services/vcresolver/client"
	"github.com/provin-line/oss/pipeline/chained"
	jsonataconv "github.com/provin-line/oss/pipeline/chained/converter/jsonata"
	"github.com/provin-line/oss/pipeline/chained/filter"
	jsonatafilter "github.com/provin-line/oss/pipeline/chained/filter/jsonata"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/provenance"
	"github.com/provin-line/oss/pipeline/provenance/chainwalk"
	"github.com/provin-line/oss/pipeline/provenance/vcdid"
	"github.com/provin-line/oss/pipeline/sink"
	"github.com/provin-line/oss/pipeline/source/aggregate"
	"github.com/provin-line/oss/pipeline/source/ingest"
	"github.com/provin-line/oss/pipeline/transport"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	natstransport "github.com/provin-line/oss/pipeline/transport/nats"
	"github.com/provin-line/oss/resolver"
	"github.com/provin-line/oss/tlog/memlog"
	"github.com/provin-line/oss/vc"
)

// The vcresolver client is the network credential resolver a full-chain verifier walks.
// The compile-time CredentialResolver assertion lives here (the consumer that imports
// both network/ and pipeline/), keeping the client package free of any pipeline/ import.
var _ chainwalk.CredentialResolver = (*vcresolverclient.Resolver)(nil)

// dataPlaneDeps are the cross-plane dependencies a data plane needs beyond its own
// keystore: the shared DID resolver (sink loops verify upstream credentials through it)
// and the sink Writer (where a sink delivers consumed events). They are zero for a
// source-only node — a source loop uses neither.
type dataPlaneDeps struct {
	Resolver   resolver.Resolver
	SinkWriter sink.Writer
	// VCStore is the node's local VC store (the local *vcresolver.Service StoreVC seam).
	// Consuming loops (sink, chained) store every verified ingress credential through it,
	// populating the unresolved pool for the async chain-audit path (D-17f-1, D-17f-7).
	// Nil is a boot error for any consuming loop; a source-only node needs none.
	VCStore ingressStorer
	// VCStoreHTTPClient is the transport for the VC-store client; nil => http.DefaultClient.
	// Tests inject an embedded server's client here. The VC-store endpoint and bearer are
	// node config (pipelineconfig.Config), not deps — so main, which loads and passes that
	// config, wires them without a separate composition step.
	VCStoreHTTPClient connect.HTTPClient
	// AuditQueue registers each consumed head for async audit (slice-17h, D-17h-2). Nil
	// disables registration (a node/test without the audit runner); main always wires it.
	AuditQueue auditRegistrar
	// Receipts records the emit-time consumed-set receipt for an aggregate's own emission
	// (slice-17o), enabling emit-locus source-commitment self-audit. Nil (with AuditQueue)
	// leaves an aggregate broadcast-only (no self-audit); main always wires it.
	Receipts receiptWriter
}

// dataPlane is the node's set of running pipeline loops over one shared nats
// connection. It owns the connection's lifecycle: Run starts the loops, waits for
// them to drain on context cancellation, then closes the shared connection (the 17a
// Conn-owns-teardown contract realized at node level).
type dataPlane struct {
	conn       *natstransport.Conn // nil when there are zero loops
	loops      []*transport.Loop
	aggregates []*aggregate.Process // self-triggered aggregate processes (contract.Process)
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
	// When a vc-store-endpoint is configured, build the network VC-store client once:
	// producing loops publish issued credentials through it. Absent => no publication.
	var vcClient *vcresolverclient.Resolver
	if pipeCfg.VCStoreEndpoint != "" {
		httpClient := deps.VCStoreHTTPClient
		if httpClient == nil {
			httpClient = http.DefaultClient
		}
		vcClient = vcresolverclient.New(vcpbconnect.NewVCResolverServiceClient(
			httpClient, pipeCfg.VCStoreEndpoint,
			connect.WithInterceptors(bearerInterceptor(pipeCfg.VCStoreBearer)),
			connect.WithReadMaxBytes(pipeCfg.MaxCredentialSize), // D-17g-13: bound a resolved VC (protects 17e's full walk)
		))
	}
	// Consuming loops (sink, chained) share one verifier (over the node's resolver) and one
	// in-memory ingress store, built lazily on the first such loop so a source-only node
	// needs no resolver. ensureConsumer builds them once and fails closed without a resolver.
	// Full-chain verification is the async audit runner's job (slice-17h), not a real-time
	// per-loop verifier (slice-17j retired "full").
	var verifier *vc.Verifier
	var ingressStore contract.IngressVCStore
	ensureConsumer := func(loopName string) error {
		if verifier != nil {
			return nil
		}
		if deps.Resolver == nil {
			return fmt.Errorf("standalone: loop %q: consuming role requires a DID resolver", loopName)
		}
		if deps.VCStore == nil {
			return fmt.Errorf("standalone: loop %q: consuming role requires a VC store", loopName)
		}
		verifier = vc.NewVerifier(deps.Resolver, ed25519.Verifier{})
		ingressStore = &serviceIngressStore{store: deps.VCStore, audit: deps.AuditQueue}
		return nil
	}
	// publisher is non-nil exactly when a vc-store-endpoint is configured; producing loops
	// wrap their signer with it so issued credentials reach the store (fail-closed).
	var publisher credentialPublisher
	if vcClient != nil {
		publisher = vcClient
	}
	for _, lc := range pipeCfg.Loops {
		var loop *transport.Loop
		switch lc.Role {
		case pipelineconfig.RoleSource:
			loop, err = buildSourceLoop(conn, builder, publisher, lc)
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
				loop, err = buildChainedLoop(conn, builder, publisher, verifier, ingressStore, lc)
			}
		case pipelineconfig.RoleAggregate:
			// An aggregate is a consuming producer (verifies+stores N ingress inputs,
			// emits a FirstDrop) and implements contract.Process directly (it owns its
			// window timer), so it is tracked in dp.aggregates, not dp.loops.
			var agg *aggregate.Process
			if err = ensureConsumer(lc.Name); err == nil {
				// Emit-locus self-audit (slice-17o): the aggregate registers each emitted head
				// (local store + receipt + queue + optional remote publish) BEFORE broadcasting.
				// Wired only when the audit substrate is present; nil leaves it broadcast-only.
				var registrar aggregate.EmissionRegistrar
				if deps.Receipts != nil && deps.AuditQueue != nil {
					registrar = &emissionRegistrar{
						local:     deps.VCStore,
						receipts:  deps.Receipts,
						audit:     deps.AuditQueue,
						publisher: publisher,
					}
				}
				agg, err = buildAggregateProcess(conn, builder, verifier, ingressStore, registrar, lc)
			}
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			dp.aggregates = append(dp.aggregates, agg)
			continue
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
func buildSourceLoop(conn *natstransport.Conn, builder *vc.Builder, publisher credentialPublisher, lc pipelineconfig.LoopConfig) (*transport.Loop, error) {
	src := lc.Source
	if src.TransformationClaim == vc.ClaimAggregate {
		// An ingest source loop signs via SignFirstDrop (N=0, no consumed set); the
		// aggregate Source Process (pool/window + SignAggregateFirstDrop) is a later
		// slice with its own role/wiring. Fail with a legible boot error rather than
		// the raw vcdid "aggregate requires SourceRootCanonical" construction error.
		return nil, fmt.Errorf("standalone: loop %q: transformation-claim %q is not valid on an ingest source loop (the aggregate Source Process runtime is a separate slice)", lc.Name, vc.ClaimAggregate)
	}
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
	// When a VC store is configured, publish each FirstDrop (no predecessor, so no upstream
	// hint) before it is emitted downstream — fail-closed (D-17e-3).
	var sourceSigner provenance.SourceSigner = signer
	if publisher != nil {
		sourceSigner = &publishingSigner{inner: signer, publisher: publisher}
	}
	proc, err := ingest.New(ingest.Config{Signer: sourceSigner})
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
	cfg := sink.Config{
		Strategy:         strategy,
		Kind:             kind,
		Codec:            envelopecodec.New(),
		Verifier:         verifier,
		Store:            store,
		Writer:           writer,
		UpstreamEndpoint: lc.Sink.UpstreamEndpoint,
	}
	proc, err := sink.New(cfg)
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
func buildChainedLoop(conn *natstransport.Conn, builder *vc.Builder, publisher credentialPublisher, verifier provenance.Verifier, store contract.IngressVCStore, lc pipelineconfig.LoopConfig) (*transport.Loop, error) {
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
	// When a VC store is configured, publish each ChainPreserving credential (passing the
	// upstream-endpoint as the predecessor-fetch hint) before downstream emit — fail-closed.
	var chainedSigner provenance.ChainedSigner = signer
	if publisher != nil {
		chainedSigner = &publishingSigner{inner: signer, publisher: publisher, upstreamEndpoint: cc.UpstreamEndpoint}
	}
	chainedCfg := chained.Config{
		Strategy:          strategy,
		IngressConformant: true,
		UpstreamEndpoint:  cc.UpstreamEndpoint,
		Codec:             envelopecodec.New(),
		Verifier:          verifier,
		Store:             store,
		Signer:            chainedSigner,
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

// buildAggregateProcess assembles one aggregate Source Process (slice-17l): a stateful
// pool+window process that verifies+stores N ingress inputs and, on each window tick,
// folds them into a provin:aggregate FirstDrop with a multi-source commitment. The claim
// and source-root canonical (JCS) are fixed by the role; the reference ManifestFold is
// wired. When a VC store is configured the signer publishes each issued FirstDrop
// (fail-closed), like a source. The config layer has validated lc.Role is aggregate.
func buildAggregateProcess(conn *natstransport.Conn, builder *vc.Builder, verifier provenance.Verifier, store contract.IngressVCStore, registrar aggregate.EmissionRegistrar, lc pipelineconfig.LoopConfig) (*aggregate.Process, error) {
	ac := lc.Aggregate
	signer, err := vcdid.NewSigner(vcdid.Config{
		Builder:             builder,
		IssuerDID:           ac.Issuer.DID,
		KeyID:               ac.Issuer.KeyID,
		VerificationMethod:  ac.Issuer.VerificationMethod,
		PipelineID:          ac.PipelineID,
		ProcessID:           ac.ProcessID,
		TransformationClaim: vc.ClaimAggregate,
		SourceRootCanonical: vc.SourceRootCanonicalJCS,
	})
	if err != nil {
		return nil, fmt.Errorf("standalone: loop %q: aggregate signer: %w", lc.Name, err)
	}
	cfg := aggregate.Config{
		Signer:    signer,
		Verifier:  verifier,
		Store:     store,
		Publisher: conn.Publisher(ac.OutputSubject),
		Codec:     envelopecodec.New(),
		Emission:  memlog.New(),
		Fold:      aggregate.ManifestFold{},
		Window:    ac.Window,
		// SelfAudit registers each emitted head (local store + receipt + queue + optional
		// remote publish) BEFORE broadcast (slice-17o). It subsumes the issued-VC remote
		// publish that source/chained loops do via publishingSigner — so the aggregate uses
		// the PLAIN signer and does not wrap it (the publish must follow self-audit, D-17o-3).
		SelfAudit: registrar,
	}
	// ac.VerificationStrategy is config-validated to "adjacent"; the aggregate runtime
	// declares VerificationAdjacent intrinsically, so it takes no strategy field.
	for _, ing := range ac.Ingresses {
		cfg.Ingress = append(cfg.Ingress, aggregate.Ingress{
			Subscriber:       conn.Subscriber(ing.Subject),
			UpstreamEndpoint: ing.UpstreamEndpoint,
		})
	}
	proc, err := aggregate.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("standalone: loop %q: aggregate process: %w", lc.Name, err)
	}
	return proc, nil
}

// verificationStrategy maps a (config-validated) strategy token to its contract value.
// "adjacent" verifies the immediately preceding credential — the only ingress strategy
// (full-chain audit is the async audit runner's job, slice-17h; "full" was retired in 17j).
func verificationStrategy(s string) (contract.VerificationStrategy, error) {
	switch s {
	case pipelineconfig.StrategyAdjacent:
		return contract.VerificationAdjacent, nil
	default:
		return contract.VerificationUnknown, fmt.Errorf("unknown verification-strategy %q", s)
	}
}

// bearerInterceptor sets the L1 PDP Authorization bearer on every outgoing client
// request to the VC store. An empty token sets no header (an unauthenticated PoC node);
// the server-side interceptor decides whether that is acceptable.
func bearerInterceptor(token string) connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if token != "" && req.Spec().IsClient {
				req.Header().Set("Authorization", "Bearer "+token)
			}
			return next(ctx, req)
		}
	})
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

// Run runs every loop until ctx is cancelled, waits for all of them to drain and
// return, then closes the shared connection. A zero-loop runner returns immediately.
// It returns the first loop error, or the connection close error if the loops were
// clean.
//
// Loops share a child context derived from ctx, so the first loop to fail (e.g. a
// boot-time Subscribe error) cancels its siblings and Run returns promptly — it does
// not block until an external cancellation arrives.
func (d *dataPlane) Run(ctx context.Context) error {
	total := len(d.loops) + len(d.aggregates)
	if total == 0 {
		return nil
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	errs := make(chan error, total)
	// Loops and aggregates both implement contract.Process; run them uniformly. A
	// failure in any drains the siblings (cancel) instead of blocking on them.
	run := func(p contract.Process) {
		defer wg.Done()
		if err := p.Run(runCtx); err != nil {
			errs <- err
			cancel()
		}
	}
	for _, l := range d.loops {
		wg.Add(1)
		go run(l)
	}
	for _, a := range d.aggregates {
		wg.Add(1)
		go run(a)
	}
	wg.Wait()
	close(errs)

	// All processes have drained (Subscriber.Drain + Publisher.Close); only now tear the
	// shared connection down.
	closeErr := d.conn.Close()

	for err := range errs {
		if err != nil {
			return err
		}
	}
	return closeErr
}
