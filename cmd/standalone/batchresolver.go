package main

import (
	"context"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/gen/go/dplaax/vc/v1/vcpbconnect"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/batchresolver"
	vcresolverclient "github.com/provin-line/oss/network/pkg/services/vcresolver/client"
	"github.com/provin-line/oss/vc"
)

// peerFetcher implements batchresolver.Fetcher: it builds a size-bounded VCResolverService
// client per peer endpoint over the SSRF-guarded HTTP client and resolves the credential
// by content address. A fresh client per call is cheap (it wraps the shared HTTP client)
// and keeps the endpoint — which varies per pool entry — out of long-lived state.
//
// It presents the node's L1 bearer (D-17g-10): a real peer mounts VCResolverService behind
// the auth interceptor, so an unauthenticated fetch would be rejected and the chain would
// never assemble. It reuses the same VCStoreBearer producing loops use to publish (17e) —
// a single-realm PoC posture; per-peer / cross-realm audit authorization is a later slice.
type peerFetcher struct {
	httpClient connect.HTTPClient // the SSRF-guarded client (guard.HTTPClient())
	bearer     string             // the node's L1 PDP token (pipeline vc-store-bearer)
	maxBytes   int                // per-credential read cap (D-17g-13)
}

func (f *peerFetcher) Fetch(ctx context.Context, endpoint, contentAddress string) (*vc.PipelinePassCredential, error) {
	c := vcresolverclient.New(vcpbconnect.NewVCResolverServiceClient(
		f.httpClient, endpoint,
		connect.WithInterceptors(bearerInterceptor(f.bearer)),
		connect.WithReadMaxBytes(f.maxBytes),
	))
	return c.ResolveCredential(ctx, contentAddress)
}

// hasConsumingLoop reports whether the node runs a sink or chained loop — the population
// that performs verified-ingress storage and so accumulates unresolved predecessor holes.
func hasConsumingLoop(pipeCfg *pipelineconfig.Config) bool {
	for _, lc := range pipeCfg.Loops {
		if lc.Role == pipelineconfig.RoleSink || lc.Role == pipelineconfig.RoleChained {
			return true
		}
	}
	return false
}

// buildBatchResolver constructs the async chain-audit runner, or returns (nil, nil) when
// the node has no consuming loop (a source-only node accumulates no holes, so there is
// nothing to drain). pool and submitter are the shared instances main threads into the
// VC resolver service, so the runner drains exactly the pool StoreVC feeds.
func buildBatchResolver(
	pool batchresolver.Pool,
	submitter batchresolver.Submitter,
	guard *core.URLGuard,
	didResolver batchresolver.DIDResolver,
	pipeCfg *pipelineconfig.Config,
) (*batchresolver.Runner, error) {
	if !hasConsumingLoop(pipeCfg) {
		return nil, nil
	}
	fetcher := &peerFetcher{httpClient: guard.HTTPClient(), bearer: pipeCfg.VCStoreBearer, maxBytes: pipeCfg.MaxCredentialSize}
	return batchresolver.New(pool, submitter, fetcher, didResolver, guard, batchresolver.Config{
		Interval:   pipeCfg.BatchResolver.Interval,
		BatchSize:  pipeCfg.BatchResolver.BatchSize,
		MaxRetries: pipeCfg.BatchResolver.MaxRetries,
		MaxDepth:   pipeCfg.BatchResolver.MaxDepth,
	})
}
