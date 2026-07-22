package main

// Mirror-shipper wiring (PR3b Task 7, tlog-custody spec D-T6): this binary
// wires one tlogship.Shipper per durable custody log pipeline/runtime.
// Runtime.CustodyLogs() reports — every local durable log this node opened,
// sink-reject logs included (D6) — shipping through a
// network/pkg/services/tlogservice/client.Client signed as that SPECIFIC
// log's own checkpoint signer identity (tlog-custody spec D-T3: checkpoint
// signer == wireauth signer). A node whose loops span several local
// identities (a source issuer, an archival sink's receipt/reject issuer, an
// aggregate's own issuer) needs one signing client per identity, mirroring
// this file's own auditClientFactory (wiring.go) and reportclientFactory
// (emithealthwiring.go) exactly.

import (
	"fmt"
	"sync"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	tlogserviceclient "github.com/provin-line/oss/network/pkg/services/tlogservice/client"
	pipelineruntime "github.com/provin-line/oss/pipeline/runtime"
	"github.com/provin-line/oss/pipeline/transport/tlogship"
)

// mirrorClientFactory builds and caches one tlogservice/client.Client per
// checkpoint-signer identity (DID). Safe for concurrent use.
type mirrorClientFactory struct {
	signer     crypto.Signer
	baseURL    string
	bearer     string
	httpClient connect.HTTPClient

	mu      sync.Mutex
	clients map[string]*tlogserviceclient.Client
}

func newMirrorClientFactory(signer crypto.Signer, baseURL, bearer string, httpClient connect.HTTPClient) *mirrorClientFactory {
	return &mirrorClientFactory{signer: signer, baseURL: baseURL, bearer: bearer, httpClient: httpClient, clients: map[string]*tlogserviceclient.Client{}}
}

// For returns the cached client signing as signerDID, building and caching
// one on first use.
func (f *mirrorClientFactory) For(signerDID string) *tlogserviceclient.Client {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.clients[signerDID]; ok {
		return c
	}
	c := tlogserviceclient.New(tlogserviceclient.Config{
		Signer:     f.signer,
		SignerDID:  signerDID,
		BaseURL:    f.baseURL,
		HTTPClient: f.httpClient,
		Bearer:     f.bearer,
	})
	f.clients[signerDID] = c
	return c
}

// forClient adapts For to buildShippers' mirrorClientFor seam
// (tlogship.MirrorClient, not the concrete *tlogserviceclient.Client) —
// *tlogserviceclient.Client satisfies tlogship.MirrorClient structurally
// (see that package's own doc for why the interface lives there rather than
// being imported from network/).
func (f *mirrorClientFactory) forClient(signerDID string) tlogship.MirrorClient {
	return f.For(signerDID)
}

// buildShippers constructs one tlogship.Shipper per entry in custody
// (pipeline/runtime.Runtime.CustodyLogs — every durable local log this node
// opened, reject logs included), each shipping through
// mirrorClientFor(entry's checkpoint-signer DID). Caps and FlushInterval come
// from tm (provin.network.pipeline.tlog-mirror, tlog-custody spec D-T2/D-T6).
// mirrorClientFor is a function value (not the concrete *mirrorClientFactory)
// so tests can supply a spy without a live wire round trip. An empty custody
// (the memlog unit-test fallback, or a config with no durable logs
// configured) yields zero shippers — nothing to mirror.
func buildShippers(custody []pipelineruntime.CustodyLog, mirrorClientFor func(signerDID string) tlogship.MirrorClient, tm pipelineconfig.TlogMirrorConfig) ([]*tlogship.Shipper, error) {
	shippers := make([]*tlogship.Shipper, 0, len(custody))
	for _, c := range custody {
		sh, err := tlogship.New(c.Log, c.LogID, mirrorClientFor(c.Signer.DID), tlogship.Config{
			MaxBatchRecords: tm.MaxBatchRecords,
			MaxBatchBytes:   tm.MaxBatchBytes,
			FlushInterval:   tm.FlushInterval,
		})
		if err != nil {
			return nil, fmt.Errorf("pipeline: mirror shipper for custody log %q (signer %s): %w", c.LogID, c.Signer.DID, err)
		}
		shippers = append(shippers, sh)
	}
	return shippers, nil
}
