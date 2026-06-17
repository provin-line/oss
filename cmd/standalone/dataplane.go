package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/provenance/vcdid"
	"github.com/provin-line/oss/pipeline/source/ingest"
	"github.com/provin-line/oss/pipeline/transport"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	natstransport "github.com/provin-line/oss/pipeline/transport/nats"
	"github.com/provin-line/oss/tlog/memlog"
	"github.com/provin-line/oss/vc"
)

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
// loop per config entry over that shared connection.
func buildDataPlane(chainCfg *chainconfig.Config, pipeCfg *pipelineconfig.Config, keyStore keystore.KeyStore) (*dataPlane, error) {
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
	for _, lc := range pipeCfg.Loops {
		loop, err := buildSourceLoop(conn, builder, lc)
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
	signer, err := vcdid.NewSigner(vcdid.Config{
		Builder:             builder,
		IssuerDID:           lc.Issuer.DID,
		KeyID:               lc.Issuer.KeyID,
		VerificationMethod:  lc.Issuer.VerificationMethod,
		PipelineID:          lc.PipelineID,
		ProcessID:           lc.ProcessID,
		TransformationClaim: lc.TransformationClaim,
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
		Publisher:  conn.Publisher(lc.OutputSubject),
		Codec:      envelopecodec.New(),
		Emission:   memlog.New(),
	})
	if err != nil {
		return nil, fmt.Errorf("standalone: loop %q: build loop: %w", lc.Name, err)
	}
	return loop, nil
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
