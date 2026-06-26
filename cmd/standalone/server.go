package main

import (
	"fmt"
	"net/http"
	"path/filepath"

	"connectrpc.com/connect"
	"github.com/o3co/protobuf.interceptors/endpoint"

	"github.com/provin-line/oss/crypto/ed25519"
	chainpbconnect "github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
	didpbconnect "github.com/provin-line/oss/gen/go/dplaax/did/v1/didpbconnect"
	schemapbconnect "github.com/provin-line/oss/gen/go/dplaax/schema/v1/schemapbconnect"
	signerpbconnect "github.com/provin-line/oss/gen/go/dplaax/signer/v1/signerpbconnect"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/auth"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/didresolver"
	"github.com/provin-line/oss/network/pkg/registry"
	"github.com/provin-line/oss/network/pkg/services/chainmanager"
	chainhandler "github.com/provin-line/oss/network/pkg/services/chainmanager/handler"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/peerclient"
	chainyaml "github.com/provin-line/oss/network/pkg/services/chainmanager/store/yamlstore"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
	"github.com/provin-line/oss/network/pkg/services/didregistry"
	didhandler "github.com/provin-line/oss/network/pkg/services/didregistry/handler"
	didyaml "github.com/provin-line/oss/network/pkg/services/didregistry/store/yamlstore"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry"
	schemahandler "github.com/provin-line/oss/network/pkg/services/schemaregistry/handler"
	schemayaml "github.com/provin-line/oss/network/pkg/services/schemaregistry/store/yamlstore"
	"github.com/provin-line/oss/network/pkg/services/signer"
	signerhandler "github.com/provin-line/oss/network/pkg/services/signer/handler"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	vchandler "github.com/provin-line/oss/network/pkg/services/vcresolver/handler"

	vcpbconnect "github.com/provin-line/oss/gen/go/dplaax/vc/v1/vcpbconnect"
)

// BuildHandler wires the services into one mux: the Connect RPC services
// sit behind the L1 authorization interceptors (verifier injected — main builds
// it from config, tests inject a static endpoint), while the public W3C DID
// resolution route and /healthz are mounted unauthenticated. Stores root under
// the core data dir in fixed subdirs (dids/, schemas/, keys/, chain/) so they
// never cohabit. The registry id and service endpoints come from the registry
// config.
//
// It is the testable seam: the boot e2e exercises the assembled mux over httptest
// without binding a port; main wraps the returned handler in h2c and serves it.
// newDIDResolution builds the SSRF guard and the cross-registry DID resolver shared by
// the control plane (BuildHandler) and the data plane (sink-loop credential
// verification, slice-17c). The base-URL seam lets a deployment (or the boot/capstone
// e2e) override the default https://{registry} mapping (D-m6).
func newDIDResolution(coreCfg *core.CoreConfig, chainCfg *chainconfig.Config) (*core.URLGuard, *didresolver.Resolver) {
	guard := core.NewURLGuard(core.WithAllowLoopback(coreCfg.AllowLoopback))
	var resolverOpts []didresolver.Option
	if chainCfg.Transport == chainconfig.TransportNATS && chainCfg.NATS.ResolverBaseURL != "" {
		base := chainCfg.NATS.ResolverBaseURL
		resolverOpts = append(resolverOpts, didresolver.WithRegistryBaseURL(func(string) (string, error) { return base, nil }))
	}
	return guard, didresolver.New(guard, resolverOpts...)
}

// The guard (SSRF policy) and resolver (cross-registry DID resolution) are built by
// the composition root (main) and passed in, because the data plane's sink loops need
// the SAME resolver to verify upstream credentials (slice-17c) — building it once in
// main and sharing it keeps a single DID-resolution policy across both planes.
// vcSvc is the node's local VC resolver service, built in main and shared with the
// data plane's ingress store so consumed credentials are immediately resolvable over
// the VCResolverService RPC (D-17f-5). main builds it once before calling BuildHandler.
func BuildHandler(coreCfg *core.CoreConfig, regCfg *registry.RegistryConfig, chainCfg *chainconfig.Config, verifier endpoint.VerifierEndpoint, guard *core.URLGuard, resolver *didresolver.Resolver, vcSvc *vcresolver.Service) (http.Handler, error) {
	keyStore := filestore.New(filepath.Join(coreCfg.DataDir, "keys"))
	schemaStore := schemayaml.New(filepath.Join(coreCfg.DataDir, "schemas"))
	didStore := didyaml.New(filepath.Join(coreCfg.DataDir, "dids"))

	schemaSvc := schemaregistry.New(schemaStore)
	signerSvc := signer.New(ed25519.NewSigner(keyStore))
	didSvc := didregistry.New(
		didStore, keyStore, ed25519.Generator{}, ed25519.Verifier{}, regCfg.ID,
		didregistry.WithServiceEndpoints(regCfg.Endpoints),
	)
	// Chain stores share a fixed chain/ subdir; each nests its own subscriptions/
	// and allowlists/ tree under it. C2b-2a mounts BOTH chain surfaces (operator/L1
	// and peer/L2) from one Service instance with the subscriber side fully wired.
	chainRoot := filepath.Join(coreCfg.DataDir, "chain")

	chainOp, err := chainOperator(chainCfg)
	if err != nil {
		return nil, err
	}
	// KNOWN LIMITATION (deferred to C2b-2b — operator claim-state persistence):
	// the nats operator starts with EMPTY in-memory claims and is not rehydrated
	// from the persisted subscription store / existing account JWT. After a restart
	// with pre-existing subscriptions, a Remove will no-op and the next Add will
	// re-publish an account JWT carrying only the new grant (dropping prior live
	// grants). C2b-2b adds rehydration (replay the store, or load the published
	// JWT on New) alongside the live-update publisher.
	// The subscriber-side peer client signs as the node's DID with its keystore
	// #auth key (composed here — the service layer stays proto-free, slice-13
	// D-r5). nodeDID is empty for the noop/dev transport (no subscriber identity).
	nodeDID := ""
	if chainCfg.Transport == chainconfig.TransportNATS {
		nodeDID = chainCfg.NATS.NodeDID
	}
	peerCli := peerclient.New(ed25519.NewSigner(keyStore), nodeDID, guard.HTTPClient())

	chainSvc := chainmanager.New(
		chainyaml.NewSubscriptionStore(chainRoot), chainyaml.NewAllowListStore(chainRoot),
		chainmanager.WithInfraOperator(chainOp),
		chainmanager.WithDIDResolver(resolver),
		chainmanager.WithPeerClient(peerCli),
		chainmanager.WithEndpointGuard(guard),
	)

	// The peer surface verifies each RPC in-band via L2 wireauth (signer #auth key
	// resolved through the same resolver); it carries NO L1 interceptor.
	peerVerifier, err := wireauth.NewVerifier(wireauth.VerifierConfig{
		Resolver: resolver,
		Crypto:   ed25519.Verifier{},
		Nonces:   wireauth.NewMemoryNonceStore(),
	})
	if err != nil {
		return nil, fmt.Errorf("standalone: chain peer verifier: %w", err)
	}

	authz := connect.WithInterceptors(auth.Interceptors(verifier)...)

	mux := http.NewServeMux()
	for _, p := range []handlerPair{
		newPair(schemapbconnect.NewSchemaServiceHandler(schemahandler.New(schemaSvc), authz)),
		newPair(didpbconnect.NewDIDServiceHandler(didhandler.New(didSvc), authz)),
		newPair(signerpbconnect.NewSignerServiceHandler(signerhandler.New(signerSvc), authz)),
		newPair(vcpbconnect.NewVCResolverServiceHandler(vchandler.New(vcSvc), authz)),
		newPair(chainpbconnect.NewChainServiceHandler(chainhandler.NewOperator(chainSvc, chainhandler.WithSubscriber(chainSvc)), authz)),
	} {
		mux.Handle(p.path, p.h)
	}

	// ChainPeerService is the internet-facing L2 surface: mounted WITHOUT the L1
	// authz interceptor (its trust is the per-RPC wireauth proof, slice-11).
	peerPath, peerHandler := chainpbconnect.NewChainPeerServiceHandler(chainhandler.NewPeer(chainSvc, peerVerifier))
	mux.Handle(peerPath, peerHandler)

	// Public, unauthenticated routes: W3C DID resolution (open read, slice-4) and
	// liveness. These deliberately carry no authz interceptor.
	mux.Handle("/did/", didhandler.NewResolutionHandler(didSvc, regCfg.ID))
	mux.HandleFunc("/healthz", healthz)

	return mux, nil
}

type handlerPair struct {
	path string
	h    http.Handler
}

// newPair adapts the (path, handler) pair every generated NewXServiceHandler
// returns into a struct for uniform mux registration.
func newPair(path string, h http.Handler) handlerPair {
	return handlerPair{path: path, h: h}
}

func healthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}
