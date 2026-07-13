package main

import (
	"fmt"
	"net/http"
	"path/filepath"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/crypto/ed25519"
	chainpbconnect "github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
	didpbconnect "github.com/provin-line/oss/gen/go/dplaax/did/v1/didpbconnect"
	payloadpbconnect "github.com/provin-line/oss/gen/go/dplaax/payload/v1/payloadpbconnect"
	schemapbconnect "github.com/provin-line/oss/gen/go/dplaax/schema/v1/schemapbconnect"
	signerpbconnect "github.com/provin-line/oss/gen/go/dplaax/signer/v1/signerpbconnect"
	"github.com/provin-line/oss/gen/go/dplaax/tlog/v1/tlogpbconnect"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/auth"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/didresolver"
	"github.com/provin-line/oss/network/pkg/registry"
	"github.com/provin-line/oss/network/pkg/services/auditor"
	audithandler "github.com/provin-line/oss/network/pkg/services/auditor/handler"
	"github.com/provin-line/oss/network/pkg/services/chainmanager"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/evidence"
	chainhandler "github.com/provin-line/oss/network/pkg/services/chainmanager/handler"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/infra"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/peerclient"
	chainyaml "github.com/provin-line/oss/network/pkg/services/chainmanager/store/yamlstore"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
	"github.com/provin-line/oss/network/pkg/services/didregistry"
	didhandler "github.com/provin-line/oss/network/pkg/services/didregistry/handler"
	didyaml "github.com/provin-line/oss/network/pkg/services/didregistry/store/yamlstore"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver"
	payloadhandler "github.com/provin-line/oss/network/pkg/services/payloadresolver/handler"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry"
	schemahandler "github.com/provin-line/oss/network/pkg/services/schemaregistry/handler"
	"github.com/provin-line/oss/network/pkg/services/signer"
	signerhandler "github.com/provin-line/oss/network/pkg/services/signer/handler"
	"github.com/provin-line/oss/network/pkg/services/tlogservice"
	tloghandler "github.com/provin-line/oss/network/pkg/services/tlogservice/handler"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	vchandler "github.com/provin-line/oss/network/pkg/services/vcresolver/handler"
	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/tlog/filelog"

	auditpbconnect "github.com/provin-line/oss/gen/go/dplaax/audit/v1/auditpbconnect"
	vcpbconnect "github.com/provin-line/oss/gen/go/dplaax/vc/v1/vcpbconnect"
)

// BuildHandler wires the services into one mux: the Connect RPC services
// sit behind the L1 authorization interceptors (verifier injected — main builds
// it from config, tests inject a static endpoint), while the public W3C DID
// resolution route, /healthz (liveness), and /readyz (readiness, fed by the
// caller-assembled checks) are mounted unauthenticated. Stores root under
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
	guard := core.NewURLGuard(
		core.WithAllowLoopback(coreCfg.AllowLoopback),
		core.WithAllowPrivateNetworks(coreCfg.AllowPrivateNetworks),
	)
	var resolverOpts []didresolver.Option
	if chainCfg.Transport == chainconfig.TransportNATS {
		switch {
		case len(chainCfg.NATS.RegistryBaseURLs) > 0:
			resolverOpts = append(resolverOpts, didresolver.WithRegistryBaseURL(registryBaseURL(chainCfg.NATS.RegistryBaseURLs)))
		case chainCfg.NATS.ResolverBaseURL != "":
			base := chainCfg.NATS.ResolverBaseURL
			resolverOpts = append(resolverOpts, didresolver.WithRegistryBaseURL(func(string) (string, error) { return base, nil }))
		}
	}
	return guard, didresolver.New(guard, resolverOpts...)
}

// registryBaseURL derives a registry's resolution base URL from the configured
// per-registry map; an unmapped registry falls back to the didresolver default
// (https://{registry}), so a partial map for local/VPC peers composes with
// public registries.
func registryBaseURL(urls map[string]string) func(registry string) (string, error) {
	return func(registry string) (string, error) {
		if base, ok := urls[registry]; ok {
			return base, nil
		}
		return didresolver.DefaultBaseURL(registry)
	}
}

// The guard (SSRF policy) and resolver (cross-registry DID resolution) are built by
// the composition root (main) and passed in, because the data plane's sink loops need
// the SAME resolver to verify upstream credentials (slice-17c) — building it once in
// main and sharing it keeps a single DID-resolution policy across both planes.
// vcSvc is the node's local VC resolver service, built in main and shared with the
// data plane's ingress store so consumed credentials are immediately resolvable over
// the VCResolverService RPC (D-17f-5). main builds it once before calling BuildHandler.
// maxCredentialSize bounds an inbound StoreVC body (D-17g-13): a peer must not OOM the
// node with a bloated credential.
// auditStatus is the audit-verdict store the async runner writes (slice-17h) and the
// AuditService reads (slice-17i, D-17i-7); main builds it once and shares the one instance
// across both. A read-only surface — the API never mutates it.
// chainOp is the chain transport operator, built by main via chainOperator BEFORE the
// data plane (its construction publishes the node account's claims — a broker
// side-effect the data plane's connect depends on; hiding it here would re-create the
// fresh-boot ordering bug the extraction fixed).
// ingest is the HTTP push surface of the data plane's push-enabled source loops
// (zero-valued when none: no routes mounted).
// nodeDIDOf returns the node's subscriber identity DID, or "" for the noop/dev
// transport (no subscriber identity). Shared by the chain peer client and the
// payload fetch client.
func nodeDIDOf(chainCfg *chainconfig.Config) string {
	if chainCfg.Transport == chainconfig.TransportNATS {
		return chainCfg.NATS.NodeDID
	}
	return ""
}

func BuildHandler(coreCfg *core.CoreConfig, regCfg *registry.RegistryConfig, chainCfg *chainconfig.Config, chainOp infra.Operator, verifier auth.Verifier, guard *core.URLGuard, resolver *didresolver.Resolver, vcSvc *vcresolver.Service, auditStatus auditor.StatusStore, auditReceipts auditor.ReceiptReader, schemaSvc *schemaregistry.Service, payloadSvc *payloadresolver.Service, tlogs map[string]tlog.Log, maxCredentialSize int, ingest ingestMounts, readiness []readinessCheck, byRefHealthy func() bool) (http.Handler, error) {
	keyStore := filestore.New(filepath.Join(coreCfg.DataDir, "keys"))
	didStore := didyaml.New(filepath.Join(coreCfg.DataDir, "dids"))

	// schemaSvc is built by main (shared with the data plane's schema wiring).
	signerSvc := signer.New(keyStore)
	didSvc := didregistry.New(
		didStore, keyStore, ed25519.Generator{}, ed25519.Verifier{}, regCfg.ID,
		didregistry.WithServiceEndpoints(regCfg.Endpoints),
	)
	// Chain stores share a fixed chain/ subdir; each nests its own subscriptions/
	// and allowlists/ tree under it. C2b-2a mounts BOTH chain surfaces (operator/L1
	// and peer/L2) from one Service instance with the subscriber side fully wired.
	chainRoot := filepath.Join(coreCfg.DataDir, "chain")

	// The subscriber-side peer client signs as the node's DID with its keystore
	// #auth key (composed here — the service layer stays proto-free, slice-13
	// D-r5). nodeDID is empty for the noop/dev transport (no subscriber identity).
	nodeDID := nodeDIDOf(chainCfg)
	peerCli := peerclient.New(keyStore, nodeDID, guard.HTTPClient())

	chainOpts := []chainmanager.Option{
		chainmanager.WithInfraOperator(chainOp),
		chainmanager.WithDIDResolver(resolver),
		chainmanager.WithPeerClient(peerCli),
		chainmanager.WithEndpointGuard(guard),
		// This node runs the by-reference payload serving boundary (mounted below).
		chainmanager.WithPayloadServing(),
	}
	// The composition root supplies a runtime health gate (derived from the
	// producing loops' stripped-publish health) so by-reference advertisement is
	// dropped while emission is failing (export-seam D-5 degradation). Absent it,
	// advertising is governed solely by WithPayloadServing.
	if byRefHealthy != nil {
		chainOpts = append(chainOpts, chainmanager.WithByReferenceHealth(byRefHealthy))
	}
	chainSvc := chainmanager.New(
		chainyaml.NewSubscriptionStore(chainRoot), chainyaml.NewAllowListStore(chainRoot),
		chainOpts...,
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
		newPair(vcpbconnect.NewVCResolverServiceHandler(vchandler.New(vcSvc), authz, connect.WithReadMaxBytes(maxCredentialSize))),
		newPair(auditpbconnect.NewAuditServiceHandler(audithandler.New(auditor.NewStatusService(auditStatus, auditReceipts)), authz)),
		newPair(tlogpbconnect.NewTlogServiceHandler(tloghandler.New(tlogservice.New(tlogs)), authz)),
		newPair(chainpbconnect.NewChainServiceHandler(chainhandler.NewOperator(chainSvc, chainhandler.WithSubscriber(chainSvc), chainhandler.WithAllowListReader(chainSvc)), authz)),
	} {
		mux.Handle(p.path, p.h)
	}

	// Durable relationship-evidence log (transfer.relationship.record): each
	// verified RegisterSubscription/Disconnect snapshots the counterparty-signed
	// request + verifying key material under the chain root. Mirrors the sink
	// reject log — no checkpoint signer (the retained records already carry the
	// counterparty signature, not a signed log head).
	evFilelog, err := filelog.New(filepath.Join(chainRoot, "relationship-evidence"))
	if err != nil {
		return nil, fmt.Errorf("standalone: chain relationship evidence log: %w", err)
	}
	evLog := evidence.New(evFilelog)

	// ChainPeerService is the internet-facing L2 surface: mounted WITHOUT the L1
	// authz interceptor (its trust is the per-RPC wireauth proof, slice-11).
	peerPath, peerHandler := chainpbconnect.NewChainPeerServiceHandler(chainhandler.NewPeerWithEvidence(chainSvc, peerVerifier, evLog))
	mux.Handle(peerPath, peerHandler)

	// PayloadService is the internet-facing L2 by-reference payload serving
	// boundary: same wireauth proof + allow-list admission (chainSvc.Admit) as the
	// chain peer surface, likewise no L1 interceptor.
	payloadPath, payloadHandler := payloadpbconnect.NewPayloadServiceHandler(payloadhandler.New(payloadSvc, peerVerifier, chainSvc))
	mux.Handle(payloadPath, payloadHandler)

	// Public, unauthenticated routes: W3C DID resolution (open read, slice-4),
	// liveness, and readiness. These deliberately carry no authz interceptor.
	// /healthz stays STATIC (liveness: "restart me if this fails");
	// /readyz is dependency-aware (readiness: "route no new work here") —
	// the checks are assembled by main from what this node is configured with.
	mux.Handle("/did/", didhandler.NewResolutionHandler(didSvc, regCfg.ID))
	mux.HandleFunc("/healthz", healthz)
	mux.HandleFunc("/readyz", readyz(readiness))

	// HTTP push ingest (apipush) for push-enabled source loops: /ingest/<loop>/push
	// (PDP-guarded) and /ingest/<loop>/health (public). Zero bindings mount nothing.
	if err := mountPushRoutes(mux, ingest.bindings, verifier, ingest.maxBodySize); err != nil {
		return nil, err
	}

	return mux, nil
}

// ingestMounts is the HTTP push surface BuildHandler mounts for the data plane's
// push-enabled source loops. The zero value mounts nothing; maxBodySize must be
// positive when bindings exist (apipush.New fails closed otherwise).
type ingestMounts struct {
	bindings    []pushBinding
	maxBodySize int
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
