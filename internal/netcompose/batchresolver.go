package netcompose

import (
	"context"
	"net/http"
	"time"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/gen/go/dplaax/vc/v1/vcpbconnect"
	"github.com/provin-line/oss/internal/origin"
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
// It presents the node's L1 bearer (D-17g-10) — the VCStoreBearer producing loops use to
// publish (17e) — to a peer whose origin the operator named (pipelineconfig
// Config.PresentsCredentialTo): a peer of the realm mounts VCResolverService behind the auth
// interceptor. An endpoint comes from a StoreVC caller's hint or an issuer's DID
// document, so any other is fetched from without the bearer: the token would let its
// holder act as this node. Per-peer and cross-realm audit authorization is a later slice.
//
// A peer is another organization's server, so a fetch accepts no compression, reads
// at most maxBytes, and ends within the fetcher's timeout: the runner's context lives
// as long as the process.
type peerFetcher struct {
	httpClient           *http.Client               // the SSRF-guarded client (guard.HTTPClient())
	bearer               string                     // the node's L1 PDP token (pipeline vc-store-bearer)
	presentsCredentialTo func(endpoint string) bool // whether endpoint may be shown the credential; nil: none may
	maxBytes             int                        // per-credential read cap (D-17g-13)
	timeout              time.Duration              // per-fetch bound; peerFetchTimeout when not positive
}

// peerFetchTimeout bounds one fetch from a peer: one small unary call.
const peerFetchTimeout = 30 * time.Second

func (f *peerFetcher) fetchTimeout() time.Duration {
	if f.timeout > 0 {
		return f.timeout
	}
	return peerFetchTimeout
}

func (f *peerFetcher) Fetch(ctx context.Context, endpoint, contentAddress string) (*vc.PipelinePassCredential, error) {
	ctx, cancel := context.WithTimeout(ctx, f.fetchTimeout())
	defer cancel()
	opts := []connect.ClientOption{
		connect.WithAcceptCompression("gzip", nil, nil),
		connect.WithReadMaxBytes(f.maxBytes),
	}
	httpClient := f.httpClient
	if f.bearer != "" && f.presentsCredentialTo != nil && f.presentsCredentialTo(endpoint) {
		// The bearer goes to endpoint's origin only, not on to a server it
		// redirects to.
		httpClient = origin.Confine(httpClient)
		opts = append(opts, connect.WithInterceptors(BearerInterceptor(f.bearer)))
	}
	c := vcresolverclient.New(vcpbconnect.NewVCResolverServiceClient(httpClient, endpoint, opts...))
	return c.ResolveCredential(ctx, contentAddress)
}

// BearerInterceptor sets the L1 PDP Authorization bearer on every outgoing client
// request to the VC store. An empty token sets no header (an unauthenticated PoC node);
// the server-side interceptor decides whether that is acceptable. Exported — a
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
// a composition-root concern, not this builder's (Task 9): cmd/network has no
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
	fetcher := &peerFetcher{
		httpClient:           guard.HTTPClient(),
		bearer:               pipeCfg.VCStoreBearer,
		presentsCredentialTo: pipeCfg.PresentsCredentialTo,
		maxBytes:             pipeCfg.MaxCredentialSize,
	}
	return batchresolver.New(pool, submitter, fetcher, didResolver, guard, batchresolver.Config{
		Interval:   pipeCfg.BatchResolver.Interval,
		BatchSize:  pipeCfg.BatchResolver.BatchSize,
		MaxRetries: pipeCfg.BatchResolver.MaxRetries,
		MaxDepth:   pipeCfg.BatchResolver.MaxDepth,
	})
}
