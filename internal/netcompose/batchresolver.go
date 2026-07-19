package netcompose

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
		connect.WithInterceptors(BearerInterceptor(f.bearer)),
		connect.WithReadMaxBytes(f.maxBytes),
	))
	return c.ResolveCredential(ctx, contentAddress)
}

// BearerInterceptor sets the L1 PDP Authorization bearer on every outgoing client
// request to the VC store. An empty token sets no header (an unauthenticated PoC node);
// the server-side interceptor decides whether that is acceptable. Exported and
// relocated here from cmd/standalone/dataplane.go (its other caller, the data
// plane's VC-store client wiring, now reaches it through the compat alias) — a
// generic connect.Interceptor helper with no data-plane-specific coupling, so
// it lives beside its one netcompose consumer (peerFetcher.Fetch) rather than
// being duplicated.
func BearerInterceptor(token string) connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if token != "" && req.Spec().IsClient {
				req.Header().Set("Authorization", "Bearer "+token)
			}
			return next(ctx, req)
		}
	})
}

// BuildBatchResolver constructs the async chain-audit runner unconditionally from its
// args. Whether this node needs the runner at all — "does it have a consuming loop" — is
// a composition-root concern, not this builder's (Task 9): cmd/standalone gates at its
// call site with pipelineconfig.Config.HasConsumingLoop() (a source-only node nils the
// runner it gets back, preserving its old zero-loop behavior exactly); cmd/network has no
// local loops to gate on at all (pipeCfg.HasConsumingLoop() is always false there) and
// instead always runs this runner, boot-validating pipeCfg.VCStoreBearer directly. pool
// and submitter are the shared instances main threads into the VC resolver service, so
// the runner drains exactly the pool StoreVC feeds.
func BuildBatchResolver(
	pool batchresolver.Pool,
	submitter batchresolver.Submitter,
	guard *core.URLGuard,
	didResolver batchresolver.DIDResolver,
	pipeCfg *pipelineconfig.Config,
) (*batchresolver.Runner, error) {
	fetcher := &peerFetcher{httpClient: guard.HTTPClient(), bearer: pipeCfg.VCStoreBearer, maxBytes: pipeCfg.MaxCredentialSize}
	return batchresolver.New(pool, submitter, fetcher, didResolver, guard, batchresolver.Config{
		Interval:   pipeCfg.BatchResolver.Interval,
		BatchSize:  pipeCfg.BatchResolver.BatchSize,
		MaxRetries: pipeCfg.BatchResolver.MaxRetries,
		MaxDepth:   pipeCfg.BatchResolver.MaxDepth,
	})
}
