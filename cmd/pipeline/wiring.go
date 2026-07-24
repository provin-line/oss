package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/gen/go/dplaax/vc/v1/vcpbconnect"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/didresolver"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	auditorclient "github.com/provin-line/oss/network/pkg/services/auditor/client"
	payloadclient "github.com/provin-line/oss/network/pkg/services/payloadresolver/client"
	schemaclient "github.com/provin-line/oss/network/pkg/services/schemaregistry/client"
	vcresolverclient "github.com/provin-line/oss/network/pkg/services/vcresolver/client"
	"github.com/provin-line/oss/pipeline/contract"
	pipelineruntime "github.com/provin-line/oss/pipeline/runtime"
	"github.com/provin-line/oss/resolver"
	"github.com/provin-line/oss/vc"
)

// ─────────────────────────────────────────────────────────────────────────
// Config mapping: chainconfig.Config + pipelineconfig.Config -> pipeline/
// runtime.Config. This was originally a DELIBERATE duplicate of
// cmd/standalone's runtimewiring.go:runtimeConfigFrom (and its per-role
// mapping helpers), kept in lockstep by inspection because that function
// lived in package main of a DIFFERENT binary and so could not be imported.
// cmd/standalone is retired (PR3c); this mapping is now the only copy.
// ─────────────────────────────────────────────────────────────────────────

// pipelineRuntimeConfigFrom maps this binary's own loaded config trees into
// pipeline/runtime's network-agnostic Config. dataDir is coreCfg.DataDir;
// TlogDir/RejectLogDir derive from it exactly as the retired cmd/standalone's
// runtimeConfigFrom did (data-dir/tlog, data-dir/evidence/sink-rejects). A
// non-NATS transport WITH configured loops is a boot error naming the
// offending transport — this binary exists ONLY to run loops (main's
// zero-loop guard runs first), so by the time this is called len(cfg.Loops)
// is always > 0 and a non-NATS transport is always fatal here (unlike the
// retired cmd/standalone, which tolerated a source-only... no, ANY zero-loop
// config on a non-NATS transport, since it also served a pure control plane).
func pipelineRuntimeConfigFrom(chainCfg *chainconfig.Config, pipeCfg *pipelineconfig.Config, dataDir string) (pipelineruntime.Config, error) {
	cfg := pipelineruntime.Config{
		NATS: pipelineruntime.NATSConfig{
			URL:         chainCfg.NATS.URL,
			AccountSeed: chainCfg.NATS.AccountSeed,
			ConnectWait: chainCfg.NATS.ConnectWait,
		},
	}
	if dataDir != "" {
		cfg.TlogDir = filepath.Join(dataDir, "tlog")
		cfg.RejectLogDir = filepath.Join(dataDir, "evidence", "sink-rejects")
	}
	if chainCfg.Transport != chainconfig.TransportNATS {
		if len(pipeCfg.Loops) > 0 {
			// No "pipeline:" prefix here — main.go's log.Fatalf("pipeline: %v")
			// re-prefixes, and a doubled prefix reads like a bug.
			return pipelineruntime.Config{}, fmt.Errorf("data-plane loops require the nats transport, got %q", chainCfg.Transport)
		}
		return cfg, nil
	}
	for _, lc := range pipeCfg.Loops {
		cfg.Loops = append(cfg.Loops, loopConfigFrom(lc))
	}
	return cfg, nil
}

func issuerConfigFrom(ic pipelineconfig.IssuerConfig) pipelineruntime.IssuerConfig {
	return pipelineruntime.IssuerConfig{DID: ic.DID, KeyID: ic.KeyID, VerificationMethod: ic.VerificationMethod}
}

func sourceConfigFrom(sc pipelineconfig.SourceConfig) pipelineruntime.SourceConfig {
	return pipelineruntime.SourceConfig{
		OutputSubject:       sc.OutputSubject,
		Issuer:              issuerConfigFrom(sc.Issuer),
		PipelineID:          sc.PipelineID,
		ProcessID:           sc.ProcessID,
		TransformationClaim: sc.TransformationClaim,
		SchemaRef:           sc.SchemaRef,
		PushIngress:         sc.PushIngress,
	}
}

func sinkConfigFrom(sc pipelineconfig.SinkConfig) pipelineruntime.SinkConfig {
	return pipelineruntime.SinkConfig{
		Kind:                 sc.Kind,
		VerificationStrategy: sc.VerificationStrategy,
		UpstreamEndpoint:     sc.UpstreamEndpoint,
		PayloadDelivery:      sc.PayloadDelivery,
		AllowIssuers:         sc.AllowIssuers,
		Receipt: pipelineruntime.SinkReceiptConfig{
			Issue:      sc.Receipt.Issue,
			Issuer:     issuerConfigFrom(sc.Receipt.Issuer),
			PipelineID: sc.Receipt.PipelineID,
			ProcessID:  sc.Receipt.ProcessID,
		},
		Output: pipelineruntime.SinkOutputConfig{Type: sc.Output.Type, Path: sc.Output.Path},
	}
}

func chainedConfigFrom(cc pipelineconfig.ChainedConfig) pipelineruntime.ChainedConfig {
	return pipelineruntime.ChainedConfig{
		OutputSubject:        cc.OutputSubject,
		Issuer:               issuerConfigFrom(cc.Issuer),
		PipelineID:           cc.PipelineID,
		ProcessID:            cc.ProcessID,
		TransformationClaim:  cc.TransformationClaim,
		SchemaRef:            cc.SchemaRef,
		VerificationStrategy: cc.VerificationStrategy,
		UpstreamEndpoint:     cc.UpstreamEndpoint,
		PayloadDelivery:      cc.PayloadDelivery,
		Converter:            cc.Converter,
		Filters:              cc.Filters,
	}
}

// aggregateConfigFrom maps AggregateConfig. VerificationStrategy is
// deliberately NOT copied, mirroring the retired cmd/standalone's own
// mapping: the aggregate runtime declares VerificationAdjacent intrinsically,
// so runtime.AggregateConfig has no field for it.
func aggregateConfigFrom(ac pipelineconfig.AggregateConfig) pipelineruntime.AggregateConfig {
	out := pipelineruntime.AggregateConfig{
		OutputSubject: ac.OutputSubject,
		Issuer:        issuerConfigFrom(ac.Issuer),
		PipelineID:    ac.PipelineID,
		ProcessID:     ac.ProcessID,
		SchemaRef:     ac.SchemaRef,
		Window:        ac.Window,
	}
	for _, ing := range ac.Ingresses {
		out.Ingresses = append(out.Ingresses, pipelineruntime.AggregateIngress{
			Subject:          ing.Subject,
			UpstreamEndpoint: ing.UpstreamEndpoint,
			PayloadDelivery:  ing.PayloadDelivery,
		})
	}
	return out
}

func loopConfigFrom(lc pipelineconfig.LoopConfig) pipelineruntime.LoopConfig {
	return pipelineruntime.LoopConfig{
		Name:           lc.Name,
		Role:           lc.Role,
		IngressSubject: lc.IngressSubject,
		Source:         sourceConfigFrom(lc.Source),
		Sink:           sinkConfigFrom(lc.Sink),
		Chained:        chainedConfigFrom(lc.Chained),
		Aggregate:      aggregateConfigFrom(lc.Aggregate),
	}
}

// ─────────────────────────────────────────────────────────────────────────
// DID resolution: the outbound SSRF guard + cross-registry DID resolver.
// This is cmd/pipeline's own equivalent of internal/netcompose.
// NewDIDResolution — reconstructed directly from the packages it composes
// (network/pkg/core, network/pkg/chainconfig, network/pkg/didresolver)
// rather than imported, because netcompose itself is off-limits to this
// binary (a later depsguard test, PR3b Task 8, pins that on the production
// import graph). Keep this in lockstep with netcompose's copy by inspection.
// ─────────────────────────────────────────────────────────────────────────

// newDIDResolution builds the SSRF guard and cross-registry DID resolver
// this binary's sink/chained/aggregate loops verify upstream credentials
// through. Mirrors internal/netcompose.NewDIDResolution's F8 posture
// exactly: allow-private-networks=true requires a scoped resolution map
// (registry-base-urls or resolver-base-url), or an attacker-supplied
// registry could reach private address space via the open
// https://{registry} fallback.
func newDIDResolution(coreCfg *core.CoreConfig, chainCfg *chainconfig.Config) (*core.URLGuard, *didresolver.Resolver, error) {
	guard := core.NewURLGuard(
		core.WithAllowLoopback(coreCfg.AllowLoopback),
		core.WithAllowPrivateNetworks(coreCfg.AllowPrivateNetworks),
	)
	closeUnmapped := coreCfg.AllowPrivateNetworks
	var resolverOpts []didresolver.Option
	scoped := false
	if chainCfg.Transport == chainconfig.TransportNATS {
		switch {
		case len(chainCfg.NATS.RegistryBaseURLs) > 0:
			resolverOpts = append(resolverOpts, didresolver.WithRegistryBaseURL(registryBaseURL(chainCfg.NATS.RegistryBaseURLs, closeUnmapped)))
			scoped = true
		case chainCfg.NATS.ResolverBaseURL != "":
			base := chainCfg.NATS.ResolverBaseURL
			resolverOpts = append(resolverOpts, didresolver.WithRegistryBaseURL(func(string) (string, error) { return base, nil }))
			scoped = true
		}
	}
	if closeUnmapped && !scoped {
		return nil, nil, fmt.Errorf("core: allow-private-networks=true requires configured registry resolution (%s or %s) so an unmapped registry cannot reach private space", "provin.network.chain.nats.registry-base-urls", "provin.network.chain.nats.resolver-base-url")
	}
	return guard, didresolver.New(guard, resolverOpts...), nil
}

// registryBaseURL mirrors internal/netcompose.registryBaseURL exactly (see
// its doc for the F8 rationale).
func registryBaseURL(urls map[string]string, closeUnmapped bool) func(registry string) (string, error) {
	return func(registry string) (string, error) {
		if base, ok := urls[registry]; ok {
			return base, nil
		}
		if closeUnmapped {
			return "", fmt.Errorf("registry %q is not in the configured registry map; open fallback is disabled while allow-private-networks is set (an unmapped registry must not reach private space)", registry)
		}
		return didresolver.DefaultBaseURL(registry)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Wire Deps: pipeline/runtime.Deps implemented over network clients, all
// pointed at pipeCfg.VCStoreEndpoint — the ONE registry base URL this
// binary treats as every wire dependency's home (VCResolverService,
// AuditService, SchemaService, PayloadService/PayloadStoreService). This is
// the "all services mount on one node" assumption main's boot guard
// enforces (vc-store-endpoint + vc-store-bearer required whenever any loop
// is configured): a future multi-registry deployment that splits these
// across nodes is out of scope for PR3b (see the task brief).
// ─────────────────────────────────────────────────────────────────────────

// wireRegistrarTimeout bounds a network call made from the AuditRegistrar
// and ReceiptWriter adapters below. Both wrap pipeline/runtime interfaces
// (AuditRegistrar.Add, ReceiptWriter.Put) that were designed for a LOCAL,
// in-process implementation (the file-backed audit queue / receipt store)
// and so carry NO context.Context of their own — a real, load-bearing
// architectural gap for a WIRE implementation, flagged in this task's
// report rather than papered over silently. Chosen generously: every RPC
// these adapters make (RegisterAuditHead, RegisterEvidence, and the
// ResolveVC lookup ReceiptWriter needs) is small and fixed-shape, against
// this node's own configured registry.
const wireRegistrarTimeout = 30 * time.Second

// bearerInterceptor sets the L1 PDP Authorization bearer on every outgoing
// call. An empty token sets no header. Mirrors the identical helper
// duplicated in every leaf client package this binary composes
// (auditor/client, payloadresolver/client, schemaregistry/client) — a leaf
// client package must not import the composition root, and this
// composition root needs its own copy for the ONE client it builds
// directly from the generated stub (vcresolverclient.New takes a prebuilt
// vcpbconnect.VCResolverServiceClient, unlike its Config-based siblings).
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

// newVCStoreClient builds the shared vcresolver/client.Resolver every
// CredentialPublisher/IngressStorer/ReceiptWriter adapter below wraps,
// bounding a resolved/stored credential's read size the same way the
// retired cmd/standalone's credentialPublisherFrom did (D-17g-13).
func newVCStoreClient(pipeCfg *pipelineconfig.Config, httpClient connect.HTTPClient) *vcresolverclient.Resolver {
	return vcresolverclient.New(vcpbconnect.NewVCResolverServiceClient(
		httpClient, pipeCfg.VCStoreEndpoint,
		connect.WithInterceptors(bearerInterceptor(pipeCfg.VCStoreBearer)),
		connect.WithReadMaxBytes(pipeCfg.MaxCredentialSize),
	))
}

// vcStoreAdapter adapts *vcresolverclient.Resolver to BOTH
// pipeline/runtime.CredentialPublisher (issued-credential publish) and
// pipeline/runtime.IngressStorer (consumed/emitted-head store) — one wire
// client, two Deps seams, mirroring vcresolverclient.Resolver's own "one
// type, both directions" shape.
type vcStoreAdapter struct {
	client *vcresolverclient.Resolver
}

var (
	_ pipelineruntime.CredentialPublisher = vcStoreAdapter{}
	_ pipelineruntime.IngressStorer       = vcStoreAdapter{}
	_ contract.PayloadResolver            = wireRetryingPayloadResolver{}
)

// StoreCredential implements pipeline/runtime.CredentialPublisher.
func (a vcStoreAdapter) StoreCredential(ctx context.Context, cred *vc.PipelinePassCredential, upstreamEndpoint string) (pipelineruntime.StoredCredential, error) {
	sc, err := a.client.StoreCredential(ctx, cred, upstreamEndpoint)
	if err != nil {
		return pipelineruntime.StoredCredential{}, err
	}
	return pipelineruntime.StoredCredential{BodyAddress: sc.BodyAddress, WireVariantID: sc.WireVariantID}, nil
}

// StoreVC implements pipeline/runtime.IngressStorer over the SAME wire
// StoreVC RPC CredentialPublisher uses: the local vcresolver.Service takes
// raw credential bytes directly, but the wire client's StoreCredential
// takes a decoded *vc.PipelinePassCredential, so this decodes first
// (decoder-hygiene-exempt: PipelinePassCredential.UnmarshalJSON routes
// through canon.StrictDecoder, the same precedent vcresolverclient.
// Resolver.ResolveCredential documents). assemblyDepth is a local-only
// audit concept the wire StoreVC RPC has no field for — the handler always
// treats a wire-received credential as directly consumed (depth 0,
// network/pkg/services/vcresolver/handler.Handler.StoreVC's own doc) — and
// every pipeline/runtime call site always passes 0, so a non-zero value
// here would silently lose information a future caller meant to carry;
// fail loud instead of ignoring it.
func (a vcStoreAdapter) StoreVC(ctx context.Context, credential []byte, upstreamEndpoint string, assemblyDepth int) (pipelineruntime.StoredHead, error) {
	if assemblyDepth != 0 {
		return pipelineruntime.StoredHead{}, fmt.Errorf("pipeline: wire ingress store cannot represent assembly depth %d (the wire StoreVC RPC carries no such field; only depth 0 is supported)", assemblyDepth)
	}
	var cred vc.PipelinePassCredential
	// PipelinePassCredential.UnmarshalJSON itself routes through canon.StrictDecoder (decoder-hygiene-exempt).
	if err := json.Unmarshal(credential, &cred); err != nil {
		return pipelineruntime.StoredHead{}, fmt.Errorf("pipeline: decode credential for wire store: %w", err)
	}
	sc, err := a.client.StoreCredential(ctx, &cred, upstreamEndpoint)
	if err != nil {
		return pipelineruntime.StoredHead{}, err
	}
	return pipelineruntime.StoredHead{BodyAddress: sc.BodyAddress, WireVariantID: sc.WireVariantID}, nil
}

// auditClientFactory builds and caches one auditorclient.Client per signer
// identity (DID) — the AuditService write surface signs every call as a
// SPECIFIC identity (wireauth), so a node that registers audit records
// under more than one local identity (e.g. several aggregate loops, each
// with its own issuer) needs one client per identity rather than one
// shared client. Safe for concurrent use.
type auditClientFactory struct {
	signer     crypto.Signer
	baseURL    string
	bearer     string
	httpClient connect.HTTPClient

	mu      sync.Mutex
	clients map[string]*auditorclient.Client
}

func newAuditClientFactory(signer crypto.Signer, baseURL, bearer string, httpClient connect.HTTPClient) *auditClientFactory {
	return &auditClientFactory{signer: signer, baseURL: baseURL, bearer: bearer, httpClient: httpClient, clients: map[string]*auditorclient.Client{}}
}

// For returns the cached client signing as signerDID, building and caching
// one on first use.
func (f *auditClientFactory) For(signerDID string) *auditorclient.Client {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.clients[signerDID]; ok {
		return c
	}
	c := auditorclient.New(auditorclient.Config{
		Signer:     f.signer,
		SignerDID:  signerDID,
		BaseURL:    f.baseURL,
		HTTPClient: f.httpClient,
		Bearer:     f.bearer,
	})
	f.clients[signerDID] = c
	return c
}

// wireAuditRegistrar adapts a FIXED auditorclient.Client (this node's own
// subscriber identity, chainCfg.NATS.NodeDID — see buildDeps) to
// pipeline/runtime.AuditRegistrar. A single Deps.AuditQueue value is shared
// across every consuming loop AND the aggregate/sink-receipt self-audit
// registrars (pipeline/runtime.Build wires one instance for the whole
// node), and Add(head) carries no identity of its own — unlike
// ReceiptWriter's registrantDID, there is nothing here to key a per-issuer
// client on. Signing as the credential's OWN issuer is not an option
// either: for a consuming loop's ingress store, that issuer is a FOREIGN
// upstream process whose private key this node never holds. The node's own
// identity is therefore the only universally-correct choice — the
// wireauth handler verifies only that head_variant_address is admitted and
// the proof is valid (no ownership/authorization check on WHO registers),
// so any locally-held identity is accepted; using the node's own is the
// least surprising for an audit trail ("this node observed/consumed this
// head").
type wireAuditRegistrar struct {
	client *auditorclient.Client
}

// Add registers head for audit, retrying a boot-window CodeUnavailable
// (Task 3, wireauth-boot-epoch-retryable spec: RegisterAuditHead is
// idempotent — the server-side audit queue's Add preserves an existing
// entry's Attempts, see wireReceiptWriter's own doc — so a bounded,
// re-signing retry is safe here) via retryOnUnavailable. Each retry
// re-invokes RegisterAuditHead, which signs a fresh wireauth proof
// internally on every call (auditor/client.Client.proof) — never a resent
// cached proof.
func (a wireAuditRegistrar) Add(head pipelineruntime.StoredHead) error {
	ctx, cancel := context.WithTimeout(context.Background(), wireRegistrarTimeout)
	defer cancel()
	return retryOnUnavailable(ctx, defaultWireRetryBudget, defaultWireBackoff(), func() error {
		return a.client.RegisterAuditHead(ctx, head.WireVariantID)
	})
}

// wireReceiptWriter adapts the vcresolver/client resolver + auditClientFactory
// to pipeline/runtime.ReceiptWriter, the aggregate emission path's own
// self-audit registrar (emissionregistrar.go — the ONLY caller of
// deps.Receipts; sink receipts use AuditRegistrar alone, never
// ReceiptWriter). Put's registrantDID is always cred.Issuer() — a LOCAL
// identity this node's own pipeline-local keystore holds a key for (the
// aggregate loop's own configured issuer DID), so auditClientFactory.For
// can safely build a signing client for it.
//
// KNOWN LIMITATION: Put(headHash string, ...) receives only the emitted
// credential's BODY address (head.BodyAddress in emissionRegistrar —
// head.WireVariantID never reaches this seam), but RegisterEvidence's wire
// contract requires the WIRE VARIANT id, not a body address (P1-A — the
// registry resolves the variant server-side to prove admission). Since
// pipeline/runtime.Build calls StoreVC (via this SAME node's vcStoreAdapter)
// immediately before Put in the same call, the credential is already
// published at headHash; this adapter re-resolves it by content address and
// recomputes the variant deterministically (vc.PipelinePassCredential.
// WireVariantID(), the same derivation publishIssuedCredential's round-trip
// check uses) rather than caching the pairing across calls, trading one
// extra network round trip (aggregate self-audit registration only — a
// low-frequency, per-window-tick event, not per-credential-ingest) for a
// stateless, race-free adapter.
//
// NOTE (branch review, minor): pipeline/runtime's emissionRegistrar.
// RegisterEmission calls this Put (RegisterEvidence, over the wire) and then
// deps.AuditQueue.Add (wireAuditRegistrar, RegisterAuditHead, ALSO over the
// wire) for the SAME emitted head — both RPCs enqueue that head into the
// SAME server-side audit queue (network/pkg/services/auditor/evidence.go
// calls queue.Add from both the RegisterEvidence and RegisterAuditHead
// handlers). This double-enqueue is harmless (AuditQueue.Add is idempotent
// and preserves an existing entry's Attempts — see that package's own doc)
// and is a faithful port of the in-process topology's identical double-call
// shape; unlike there, though, each call here costs its OWN separate wire
// RPC rather than two cheap in-process function calls.
type wireReceiptWriter struct {
	resolver *vcresolverclient.Resolver
	factory  *auditClientFactory
}

// Put resolves headHash to its wire variant and registers evidence, retrying
// a boot-window CodeUnavailable on the RegisterEvidence call itself (Task 3,
// wireauth-boot-epoch-retryable spec: RegisterEvidence is idempotent — the
// server-side audit queue's Add preserves an existing entry's Attempts, see
// this type's own doc above — so a bounded, re-signing retry is safe).
// ResolveCredential (the earlier read, over the SAME wire) is not itself in
// the spec's loss-sensitive retry matrix and is left unwrapped. Each retry
// re-invokes RegisterEvidence, which signs a fresh wireauth proof internally
// on every call (auditor/client.Client.proof) — never a resent cached proof.
func (w wireReceiptWriter) Put(headHash string, registrantDID string, consumedHashes []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), wireRegistrarTimeout)
	defer cancel()
	cred, err := w.resolver.ResolveCredential(ctx, headHash)
	if err != nil {
		return fmt.Errorf("pipeline: resolve emitted credential %s for evidence registration: %w", headHash, err)
	}
	variant, err := cred.WireVariantID()
	if err != nil {
		return fmt.Errorf("pipeline: derive wire variant for emitted credential %s: %w", headHash, err)
	}
	client := w.factory.For(registrantDID)
	return retryOnUnavailable(ctx, defaultWireRetryBudget, defaultWireBackoff(), func() error {
		return client.RegisterEvidence(ctx, variant, consumedHashes)
	})
}

// wireSchemaGetter adapts *schemaclient.Client to pipeline/runtime.
// SchemaGetter (a producing loop's boot-time schema-ref resolution),
// mapping the client's own ErrNotFound to runtime's ErrSchemaNotFound
// sentinel — analogous to cmd/network's own in-process schema resolution,
// which maps the same store.ErrNotFound from the LOCAL registry service.
type wireSchemaGetter struct {
	client *schemaclient.Client
}

func (g wireSchemaGetter) Get(ctx context.Context, name, version string) (*pipelineruntime.Schema, error) {
	sc, err := g.client.GetSchema(ctx, name, version)
	if err != nil {
		if errors.Is(err, schemaclient.ErrNotFound) {
			return nil, pipelineruntime.ErrSchemaNotFound
		}
		return nil, err
	}
	return &pipelineruntime.Schema{Format: sc.Format, Body: sc.Body, Deprecated: sc.Deprecated}, nil
}

// wireSchemaBridge adapts *schemaclient.Client to vc.SchemaResolver (the
// consuming loops' verify-path schema content-hash resolution), mirroring
// internal/netcompose.SchemaBridge's error semantics EXACTLY: a malformed
// reference is vc.ErrSchemaInvalidRef (deterministic, mapped to failed); a
// definitive registry miss is vc.ErrSchemaNotFound; anything else (a
// transport/transient failure) passes through unwrapped, which the verifier
// maps to indeterminate rather than failed. This is a small, independent
// bridge — NOT netcompose.SchemaBridge reused (this binary must not import
// internal/netcompose; see the task brief) — kept in lockstep with it by
// inspection, pinned by wiring_test.go's mirrored test cases.
type wireSchemaBridge struct {
	client *schemaclient.Client
}

func (r wireSchemaBridge) ResolveSchema(ctx context.Context, ref vc.SchemaRef) (*vc.ResolvedSchema, error) {
	name, version, err := vc.ParseSchemaURI(ref.ID)
	if err != nil {
		return nil, err // ErrSchemaInvalidRef — a deterministic malformed reference (failed)
	}
	sc, err := r.client.GetSchema(ctx, name, version)
	if err != nil {
		if errors.Is(err, schemaclient.ErrNotFound) {
			return nil, fmt.Errorf("%w: %s@%s", vc.ErrSchemaNotFound, name, version)
		}
		return nil, err // transient (transport, ctx) — verifier maps to indeterminate
	}
	return &vc.ResolvedSchema{Format: sc.Format, Body: sc.Body}, nil
}

// payloadClientFactory builds and caches one payloadclient.Resolver per
// signer identity (DID) — mirrors auditClientFactory/mirrorClientFactory/
// reportClientFactory exactly. This is the D9 fix: PayloadStoreService's
// RetainPayload enforces owner_did == the wireauth-proven signer
// (storehandler's errOwnerMismatch — "the proven DID is authoritative over
// the claimed owner_did", and that package's own retain_e2e_test.go docs the
// common case outright: "a producing process retains its own emitted
// payload"). A node running more than one producing loop (each with its OWN
// output subject — source/chained/aggregate all declare one) therefore needs
// one signing client PER LOOP'S OUTPUT SUBJECT, never one client shared
// across every loop under a single node identity: a shared client can
// satisfy AT MOST one producing loop's retain calls, and every OTHER
// loop's retain then fails PermissionDenied — which (per dataplane.go's
// payloadWiring — PayloadStore wired ⇒ every producing loop dual-emits,
// D-6) aborts that loop's ENTIRE emission, not merely its by-reference
// side-channel. This is the production gap PR3b Task 9's separated e2e
// discovered (see the report's "Blocker discovered" section, now fixed
// here).
//
// The RESOLVE side (ResolvePayload, Deps.PayloadResolver) is NOT
// owner-bound: the querying actor IS the signer (nil authorizer — see
// payloadresolver/handler.Handler.ResolvePayload's own doc), admitted
// against the payload's owner ALLOW-LIST rather than required to equal the
// owner. buildDeps therefore still wires Deps.PayloadResolver from ONE
// client signing as the node identity (For(nodeDID)), sharing this SAME
// cache rather than needing a second factory.
type payloadClientFactory struct {
	signer          crypto.Signer
	storeEndpoint   string
	bearer          string
	httpClient      connect.HTTPClient
	retainChunkSize int

	mu      sync.Mutex
	clients map[string]*payloadclient.Resolver
}

// retainFrameOverhead is the bytes ON TOP OF the raw chunk payload one
// RetainPayload chunk frame costs on the wire — the protobuf oneof
// field-tag + varint length-delimiter (api/protobuf/dplaax/payload/v1/
// payload.proto's RetainPayloadRequest.chunk, field 2) plus the Connect
// streaming envelope's own per-message frame header — bytes the server's
// connect.WithReadMaxBytes(maxRetainChunkSize) mount counts against the RAW
// request body (internal/netcompose/server.go's retainChunkCap: "connect.
// WithReadMaxBytes bounds the RAW request body"), never subtracted from
// maxRetainChunkSize's own accounting. Generous relative to the actual
// ~9-byte cost so a configured cap at a round number never trips
// ResourceExhausted on its largest legitimate chunk.
const retainFrameOverhead = 64

// retainChunkSizeFor derives payloadClientFactory's outbound Retain chunk
// size from pipeCfg.MaxRetainChunkSize (P2 Codex fix, branch review: the
// payload client previously always used payloadclient.DefaultRetainChunkSize
// — 256 KiB — regardless of config, so a registry configured with a SMALLER
// max-retain-chunk-size rejected every frame at its connect.WithReadMaxBytes
// mount, aborting emission via dataplane.go's payloadWiring, D-6).
// Subtracts retainFrameOverhead so the actual over-the-wire message (chunk
// bytes + protobuf/Connect framing) never exceeds the server's configured
// cap, floored at 1 so a pathologically tiny configured cap still produces a
// valid (if inefficient) chunk size rather than silently falling through to
// <=0 and re-adopting the 256 KiB default (defeating a deliberately-small
// operator quota). A non-positive maxRetainChunkSize returns 0 unchanged —
// payloadclient.New's own <=0 → DefaultRetainChunkSize semantics apply, the
// same as an unconfigured Config.RetainChunkSize; pipelineconfig.
// LoadPipelineConfig already fails startup on a non-positive value, so this
// path is defensive-only in production (relevant only to a directly
// constructed test factory).
func retainChunkSizeFor(maxRetainChunkSize int) int {
	if maxRetainChunkSize <= 0 {
		return 0
	}
	size := maxRetainChunkSize - retainFrameOverhead
	if size < 1 {
		size = 1
	}
	return size
}

func newPayloadClientFactory(signer crypto.Signer, storeEndpoint, bearer string, httpClient connect.HTTPClient, maxRetainChunkSize int) *payloadClientFactory {
	return &payloadClientFactory{
		signer:          signer,
		storeEndpoint:   storeEndpoint,
		bearer:          bearer,
		httpClient:      httpClient,
		retainChunkSize: retainChunkSizeFor(maxRetainChunkSize),
		clients:         map[string]*payloadclient.Resolver{},
	}
}

// For returns the cached client signing as signerDID, building and caching
// one on first use.
func (f *payloadClientFactory) For(signerDID string) *payloadclient.Resolver {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.clients[signerDID]; ok {
		return c
	}
	c := payloadclient.New(payloadclient.Config{
		Signer:          f.signer,
		SignerDID:       signerDID,
		HTTPClient:      f.httpClient,
		StoreEndpoint:   f.storeEndpoint,
		Bearer:          f.bearer,
		RetainChunkSize: f.retainChunkSize,
	})
	f.clients[signerDID] = c
	return c
}

// wirePayloadStore adapts payloadClientFactory's per-owner *payloadclient.
// Resolver clients — each a (io.Reader, size) streaming Retain — to
// pipeline/runtime.PayloadRetainStore's whole-buffer Store(ctx, payload
// []byte, ownerDID string) shape — the producer half of by-reference
// delivery. Store selects factory.For(ownerDID) so each retain call signs AS
// the owning producing loop (D9 — see payloadClientFactory's doc), and
// streams to Config.StoreEndpoint (pipeCfg.VCStoreEndpoint, the same ONE
// registry base URL every other wire Dep uses).
type wirePayloadStore struct {
	factory *payloadClientFactory
}

// Store retains payload, retrying a boot-window CodeUnavailable (Task 3,
// wireauth-boot-epoch-retryable spec: RetainPayload is idempotent re-retain —
// see the spec's recovery matrix). Store still holds the whole payload as
// []byte (pipeline/runtime.PayloadRetainStore's own contract), so each retry
// rebuilds a FRESH bytes.Reader per attempt — Retain's io.Reader is consumed
// on the first attempt and cannot be replayed, which is exactly why the
// retry must live HERE (the layer holding the original bytes) rather than
// inside Retain or a transport interceptor. Each attempt also re-invokes
// Retain, which signs a fresh wireauth proof internally on every call
// (payloadresolver/client.Resolver.proof) — never a resent cached proof.
func (s wirePayloadStore) Store(ctx context.Context, payload []byte, ownerDID string) (string, error) {
	client := s.factory.For(ownerDID)
	var contentAddress string
	err := retryOnUnavailable(ctx, defaultWireRetryBudget, defaultWireBackoff(), func() error {
		var attemptErr error
		contentAddress, attemptErr = client.Retain(ctx, bytes.NewReader(payload), ownerDID, uint64(len(payload)))
		return attemptErr
	})
	return contentAddress, err
}

// wireRetryingPayloadResolver wraps a *payloadclient.Resolver's ResolvePayload
// with the same bounded, re-signing retry (Task 3, wireauth-boot-epoch-
// retryable spec): a signed READ races cmd/network's boot window exactly
// like RetainPayload does (spec's recovery matrix — ResolvePayload is an
// idempotent read), and dropping a boot-window-racing resolve aborts the
// consuming event just like a denied retain aborts an emission. Each retry
// re-invokes ResolvePayload, which signs a fresh wireauth proof internally on
// every call — never a resent cached proof.
type wireRetryingPayloadResolver struct {
	client *payloadclient.Resolver
}

func (r wireRetryingPayloadResolver) ResolvePayload(ctx context.Context, upstreamEndpoint, contentHash string) ([]byte, error) {
	var payload []byte
	err := retryOnUnavailable(ctx, defaultWireRetryBudget, defaultWireBackoff(), func() error {
		var attemptErr error
		payload, attemptErr = r.client.ResolvePayload(ctx, upstreamEndpoint, contentHash)
		return attemptErr
	})
	return payload, err
}

// buildDeps assembles pipeline/runtime.Deps entirely from WIRE clients
// pointed at pipeCfg.VCStoreEndpoint (the ONE registry base URL — see this
// file's package-level doc). keyStore is THIS binary's own pipeline-local
// keystore (DataDir/keys), never the registry's — every signing identity
// below (the node identity for AuditRegistrar/PayloadResolver, EACH
// producing loop's OWN output subject for PayloadStore/retain — see
// payloadClientFactory's doc — and each aggregate/loop issuer ReceiptWriter
// signs as) must have its #auth key provisioned there; main's boot preflight
// (D9, preflightPayloadRetainKeys) checks the producing-loop case fails
// closed at boot rather than at first emit. nodeDID is chainCfg.NATS.NodeDID,
// guaranteed non-empty by the time this runs (main's guards require the nats
// transport whenever any loop is configured, and chainconfig.
// LoadChainConfig requires node-did non-empty on that transport).
func buildDeps(pipeCfg *pipelineconfig.Config, keyStore crypto.Signer, guard *core.URLGuard, didResolver resolver.Resolver, nodeDID string) pipelineruntime.Deps {
	httpClient := guard.HTTPClient()

	vcClient := newVCStoreClient(pipeCfg, httpClient)
	store := vcStoreAdapter{client: vcClient}

	factory := newAuditClientFactory(keyStore, pipeCfg.VCStoreEndpoint, pipeCfg.VCStoreBearer, httpClient)

	schemaCli := schemaclient.New(schemaclient.Config{
		BaseURL:    pipeCfg.VCStoreEndpoint,
		HTTPClient: httpClient,
		Bearer:     pipeCfg.VCStoreBearer,
	})

	payloadFactory := newPayloadClientFactory(keyStore, pipeCfg.VCStoreEndpoint, pipeCfg.VCStoreBearer, httpClient, pipeCfg.MaxRetainChunkSize)

	return pipelineruntime.Deps{
		Resolver:            didResolver,
		VCStore:             store,
		AuditQueue:          wireAuditRegistrar{client: factory.For(nodeDID)},
		Receipts:            wireReceiptWriter{resolver: vcClient, factory: factory},
		SchemaResolver:      wireSchemaBridge{client: schemaCli},
		SchemaGetter:        wireSchemaGetter{client: schemaCli},
		PayloadStore:        wirePayloadStore{factory: payloadFactory},
		PayloadResolver:     wireRetryingPayloadResolver{client: payloadFactory.For(nodeDID)},
		CredentialPublisher: store,
	}
}

// preflightProbeData is signed (never transmitted anywhere) purely to probe
// keyStore for a key's presence — see preflightPayloadRetainKeys' doc for why
// Sign, rather than a raw-key existence check, is the right seam to probe
// through.
var preflightProbeData = []byte("cmd/pipeline: D9 payload-retain key preflight probe")

// preflightPayloadRetainKeys verifies keyStore already holds a #auth signing
// key for EVERY producing loop's own output subject (D9) — the identity
// wirePayloadStore's payloadClientFactory (this file, above) signs each
// retain call as. Without this, a misprovisioned deployment would only
// discover the gap at first emit, as a RetainPayload PermissionDenied that
// aborts the whole emission (dataplane.go's payloadWiring — PayloadStore
// wired ⇒ every producing loop dual-emits, D-6); checking here at boot turns
// that into an immediate, named failure instead.
//
// It probes via Sign (the only read keystore.KeyStore's contract exposes),
// not a raw-key existence check: this preflight must work for ANY KeyStore
// implementation the crypto.Signer seam admits (a future keep-keys-opaque
// TPM/KMS backend could never support the latter), not only filestore's.
// keyStore.Sign's error is a wrapped keystore.ErrNotFound when no key is
// held for a well-formed (did, keyID) — errors.Is distinguishes that from a
// malformed/storage failure, which is reported too (never silently passed).
func preflightPayloadRetainKeys(keyStore crypto.Signer, loops []pipelineconfig.LoopConfig) error {
	for _, ref := range producingLoops(loops) {
		if _, err := keyStore.Sign(ref.OutputSubject, string(keystore.KeyIDAuth), preflightProbeData); err != nil {
			if errors.Is(err, keystore.ErrNotFound) {
				return fmt.Errorf("producing loop %q: no signing key for output subject %s — by-reference retain signs as the owner", ref.Name, ref.OutputSubject)
			}
			return fmt.Errorf("producing loop %q: checking signing key for output subject %s: %w", ref.Name, ref.OutputSubject, err)
		}
	}
	return nil
}

// preflightWireOnlySignerKeys extends the D9 boot preflight (above) to the
// OTHER two wire-only signing identities this binary needs before it ever
// runs a loop (branch review, Important finding):
//
//  1. nodeDID — the identity wireAuditRegistrar.Add signs RegisterAuditHead
//     as (buildDeps: AuditQueue: wireAuditRegistrar{client: factory.
//     For(nodeDID)}) and PayloadResolver's ResolvePayload identity
//     (payloadFactory.For(nodeDID)). Previously this surfaced only at the
//     FIRST consuming loop's ingress consume (the first RegisterAuditHead
//     call) or the first by-reference resolve — well after boot.
//  2. every DURABLE custody log's checkpoint-signer identity (custodyLogs —
//     dp.CustodyLogs(), the SAME issuer/receipt-issuer DID the mirror
//     shipper signs MirrorLogSegment as, tlog-custody spec D-T3). filelog's
//     own arming does NOT probe the key at boot: WithCheckpointSigner
//     (tlog/filelog/filelog.go) only STORES the CheckpointSigner value on
//     the Log struct — it calls Sign nowhere in filelog.New — so a missing
//     key here previously surfaced only at that log's FIRST Checkpoint call
//     (the owning shipper's first ship attempt), as a non-fatal logged
//     shipper error (main.go's run/drainShippers never treat a shipper
//     error as fatal), not a boot failure.
//
// This must run AFTER pipelineruntime.Build (unlike preflightPayloadRetainKeys,
// which needs only pipeCfg.Loops, computable BEFORE Build): a custody log's
// checkpoint-signer identity is only fully resolved once tlog construction
// actually runs, and dp.CustodyLogs() is its one authoritative source — a
// preflight that instead re-derived the (source/chained/aggregate issuer,
// sink receipt-issuer) mapping directly from pipeCfg.Loops would duplicate
// dataplane.go's own internal logic and could silently drift from it.
// nodeDID is checked once even if it also happens to equal a custody log's
// signer (no duplicate probe/error for the same identity).
func preflightWireOnlySignerKeys(keyStore crypto.Signer, nodeDID string, custodyLogs []pipelineruntime.CustodyLog) error {
	checked := make(map[string]bool, len(custodyLogs)+1)
	if _, err := keyStore.Sign(nodeDID, string(keystore.KeyIDAuth), preflightProbeData); err != nil {
		if errors.Is(err, keystore.ErrNotFound) {
			return fmt.Errorf("node identity %s: no signing key — RegisterAuditHead and PayloadResolver's ResolvePayload sign as this identity", nodeDID)
		}
		return fmt.Errorf("node identity %s: checking signing key: %w", nodeDID, err)
	}
	checked[nodeDID] = true
	for _, cl := range custodyLogs {
		did := cl.Signer.DID
		if checked[did] {
			continue
		}
		checked[did] = true
		if _, err := keyStore.Sign(did, string(keystore.KeyIDAuth), preflightProbeData); err != nil {
			if errors.Is(err, keystore.ErrNotFound) {
				return fmt.Errorf("custody log %q: no signing key for checkpoint signer %s — the mirror shipper signs MirrorLogSegment as this identity", cl.LogID, did)
			}
			return fmt.Errorf("custody log %q: checking signing key for checkpoint signer %s: %w", cl.LogID, did, err)
		}
	}
	return nil
}
