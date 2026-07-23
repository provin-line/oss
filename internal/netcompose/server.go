package netcompose

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/crypto/ed25519"
	chainpbconnect "github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
	didpbconnect "github.com/provin-line/oss/gen/go/dplaax/did/v1/didpbconnect"
	payloadpbconnect "github.com/provin-line/oss/gen/go/dplaax/payload/v1/payloadpbconnect"
	schemapbconnect "github.com/provin-line/oss/gen/go/dplaax/schema/v1/schemapbconnect"
	signerpbconnect "github.com/provin-line/oss/gen/go/dplaax/signer/v1/signerpbconnect"
	tlogpb "github.com/provin-line/oss/gen/go/dplaax/tlog/v1"
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
	"github.com/provin-line/oss/network/pkg/services/chainmanager/emithealth"
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
	"github.com/provin-line/oss/network/pkg/services/payloadresolver/storehandler"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry"
	schemahandler "github.com/provin-line/oss/network/pkg/services/schemaregistry/handler"
	"github.com/provin-line/oss/network/pkg/services/signer"
	signerhandler "github.com/provin-line/oss/network/pkg/services/signer/handler"
	"github.com/provin-line/oss/network/pkg/services/tlogservice"
	tloghandler "github.com/provin-line/oss/network/pkg/services/tlogservice/handler"
	"github.com/provin-line/oss/network/pkg/services/tlogservice/logident"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	vchandler "github.com/provin-line/oss/network/pkg/services/vcresolver/handler"
	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/tlog/filelog"

	auditpbconnect "github.com/provin-line/oss/gen/go/dplaax/audit/v1/auditpbconnect"
	vcpbconnect "github.com/provin-line/oss/gen/go/dplaax/vc/v1/vcpbconnect"
)

// Inbound request read caps by message class. connect reads and decompresses
// the request body BEFORE the auth interceptor, and readMaxBytes=0 is
// unlimited, so every mounted service is capped to bound pre-auth allocation.
//
//   - maxProofRequestBytes: wireauth proofs + small control fields (peer,
//     payload, audit, tlog). Small and fixed-shape.
//   - maxDocumentRequestBytes: schema bodies, DID documents/delegations, and
//     full-replacement allowlists, which can legitimately be larger.
//
// The credential class (StoreVC) keeps its own maxCredentialSize (a boot
// config value). MirrorLogSegment (when a mirror store is wired) keeps its
// OWN class too, derived from the D-T2 batch-bytes cap rather than borrowed
// from maxCredentialSize — see mirrorReadCapBytes. No SEND cap is set: list
// RPCs return unpaginated results that can exceed any request cap.
const (
	maxProofRequestBytes    = 256 << 10 // 256 KiB
	maxDocumentRequestBytes = 1 << 20   // 1 MiB
)

// mirrorReadCapBytes derives MirrorLogSegment's own connect read cap from
// maxBatchBytes (tlog-mirror.max-batch-bytes, D-T2 rule 5) plus
// maxProofRequestBytes as headroom for the OTHER fields one MirrorLogSegment
// call carries alongside record_payloads_framed — the checkpoint (five
// small, fixed-shape strings/bytes) and the AuthProof (the SAME shape
// maxProofRequestBytes already sizes for). Deriving the mount cap FROM
// max-batch-bytes (rather than reusing maxCredentialSize, a value chosen for
// an unrelated class — the single-VC StoreVC/fetch path) makes the two
// structurally coherent: they can never disagree, so no operator note is
// needed to keep them in sync (Task 5 review, M-1).
//
// connect.WithReadMaxBytes bounds the RAW request body, and a Connect JSON
// client base64-encodes record_payloads_framed (~4/3 inflation, now a single
// bytes blob rather than a base64'd array of elements) plus JSON
// field-name/escaping overhead — so a legitimate max-batch-bytes batch is
// larger on the JSON wire than its decoded size. This derivation applies the
// SAME `*2 + 64 KiB` inflation OuterRequestCapBytes uses (which covers base64
// plus JSON overhead with margin, plus framing/header headroom), so a valid
// one-record JSON request is never rejected at the read cap before the
// handler's own payload-sum check runs.
//
// Used by BOTH the MirrorLogSegment mount (BuildHandler, below) and
// OuterRequestCapBytes, so the per-RPC cap and the outer raw-body cap (which
// must never be smaller than it, and which inflates this value again) can
// likewise never drift apart.
func mirrorReadCapBytes(maxBatchBytes int) int {
	return (maxBatchBytes+maxProofRequestBytes)*2 + 64<<10
}

// OuterRequestCapBytes sizes the outermost raw-request-body limit so it is
// never smaller than any legitimate request under a per-RPC read cap. It must
// cover EVERY message class — the per-RPC read caps bound the DECODED message,
// but a Connect JSON request base64-encodes a bytes field (~4/3 inflation), so
// the raw body is larger than the decoded cap. It is deliberately generous —
// the tight bounds are the per-RPC caps below it; this only closes the
// pre-Connect (h2c-upgrade) path that no interceptor guards. Relocated here
// (formerly cmd/standalone/main.go) alongside the two per-RPC constants it
// sizes against, which stay unexported/internal to this file.
//
// maxRetainPayloadSize is RetainPayload's cumulative bound, not a per-frame
// one: http.MaxBytesHandler counts TOTAL bytes read across the whole HTTP
// request, and a client-streaming RPC's frames all share ONE request for the
// life of the call — so the outer cap must admit a full-size legitimate
// retain (up to maxRetainPayloadSize), not just its largest single chunk
// (that per-chunk bound is maxRetainChunkSize, enforced separately by the
// per-RPC connect.WithReadMaxBytes mount option).
//
// maxMirrorBatchBytes is tlog-mirror.max-batch-bytes when a mirror store is
// wired (cmd/network), or 0 when it is not — a caller with no mirror store
// never mounts the MirrorLogSegment cap override, so it contributes nothing
// here (passing the config value anyway would only widen the outer cap for a
// class that caller never mounts at that width). A non-zero value is run through the
// SAME mirrorReadCapBytes derivation the mount site uses, never a bare
// max-batch-bytes, so this function and the mount can never disagree about
// what MirrorLogSegment's legitimate ceiling is.
func OuterRequestCapBytes(maxCredentialSize, maxPushBodySize, maxRetainPayloadSize, maxMirrorBatchBytes int) int {
	largest := maxCredentialSize
	candidates := []int{maxPushBodySize, maxRetainPayloadSize, maxDocumentRequestBytes, maxProofRequestBytes}
	if maxMirrorBatchBytes > 0 {
		candidates = append(candidates, mirrorReadCapBytes(maxMirrorBatchBytes))
	}
	for _, v := range candidates {
		if v > largest {
			largest = v
		}
	}
	// 2x covers base64 (~4/3) plus JSON field-name/escaping overhead with
	// margin; +64 KiB is framing/header headroom.
	return largest*2 + 64<<10
}

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
// NewDIDResolution builds the SSRF guard and the cross-registry DID resolver shared by
// the control plane (BuildHandler) and the data plane (sink-loop credential
// verification, slice-17c). The base-URL seam lets a deployment (or the boot/capstone
// e2e) override the default https://{registry} mapping (D-m6).
func NewDIDResolution(coreCfg *core.CoreConfig, chainCfg *chainconfig.Config) (*core.URLGuard, *didresolver.Resolver, error) {
	guard := core.NewURLGuard(
		core.WithAllowLoopback(coreCfg.AllowLoopback),
		core.WithAllowPrivateNetworks(coreCfg.AllowPrivateNetworks),
	)
	// F8: enabling private-network reachability closes DID resolution to the
	// configured registry set. The only pre-signature, attacker-driven outbound
	// path is DID resolution, and the attacker controls the registry segment,
	// which reaches private space ONLY via the open https://{registry} fallback.
	// So in private mode the fallback is disabled (closeUnmapped): an unmapped
	// (attacker-supplied) registry fails resolution instead of probing an
	// internal address. A single resolver-base-url is inherently closed (every
	// registry maps to the one operator base), so it satisfies the requirement.
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
		// Private mode with fully-open resolution (no map, no single base) is the
		// exact F8 hole: any attacker-supplied registry would reach private space.
		// Fail closed and tell the operator to scope resolution.
		return nil, nil, fmt.Errorf("core: allow-private-networks=true requires configured registry resolution (%s or %s) so an unmapped registry cannot reach private space", "provin.network.chain.nats.registry-base-urls", "provin.network.chain.nats.resolver-base-url")
	}
	return guard, didresolver.New(guard, resolverOpts...), nil
}

// registryBaseURL derives a registry's resolution base URL from the configured
// per-registry map. When closeUnmapped is false, an unmapped registry falls back
// to the didresolver default (https://{registry}), so a partial map for
// local/VPC peers composes with public registries. When closeUnmapped is true
// (allow-private-networks mode, F8), an unmapped registry is REFUSED — the open
// fallback would let an attacker-supplied registry name reach private space.
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
// chainOp is the chain transport operator, built by main via ChainOperator BEFORE the
// data plane (its construction publishes the node account's claims — a broker
// side-effect the data plane's connect depends on; hiding it here would re-create the
// fresh-boot ordering bug the extraction fixed).
// mountIngest, when non-nil, mounts the data plane's HTTP push-ingest routes
// onto the mux (push-enabled source loops). nil mounts nothing. The callback
// seam keeps netcompose free of any data-plane type.
// NodeDIDOf returns the node's subscriber identity DID, or "" for the noop/dev
// transport (no subscriber identity). Shared by the chain peer client and the
// payload fetch client.
func NodeDIDOf(chainCfg *chainconfig.Config) string {
	if chainCfg.Transport == chainconfig.TransportNATS {
		return chainCfg.NATS.NodeDID
	}
	return ""
}

// auditReceipts is typed as the full auditor.ReceiptStore (not just
// ReceiptReader): BuildHandler reads it for the StatusService (GetAuditStatus/
// GetConsumedSources) AND writes it for the EvidenceService (RegisterEvidence)
// — one shared instance backs both directions, same as the runner's own share
// of it (main.go's "shared between the ingress path and the audit runner").
//
// payloadStore backs PayloadStoreService's RetainPayload (storehandler) — the
// raw Store, alongside payloadSvc (the Service wrapping the SAME store for
// PayloadService's read side): RetainPayload streams directly to
// Store.StoreWriter, bypassing Service (whose Store method takes a whole
// []byte, not a stream — see payloadresolver.Store.StoreWriter's doc).
// maxRetainChunkSize/maxRetainPayloadSize are the max-retain-chunk-size /
// max-retain-payload-size config quotas (pipelineconfig).
// mirror is the D-T4 mirror-custody wiring (see MirrorWiring's doc): nil
// keeps the map-only TlogService behavior; cmd/network
// opens a mirrorstore.Store and passes it here. When non-nil, MirrorLogSegment
// additionally mounts under a CREDENTIAL-class read cap (sink-receipt
// records can carry full credentials, exceeding the proof-class cap every
// other TlogService RPC uses) — see the mounting loop below for how the two
// caps coexist on one connect service.
func BuildHandler(coreCfg *core.CoreConfig, regCfg *registry.RegistryConfig, chainCfg *chainconfig.Config, chainOp infra.Operator, verifier auth.Verifier, guard *core.URLGuard, resolver *didresolver.Resolver, vcSvc *vcresolver.Service, auditStatus auditor.StatusStore, auditReceipts auditor.ReceiptStore, auditQueue auditor.AuditQueue, schemaSvc *schemaregistry.Service, payloadSvc *payloadresolver.Service, payloadStore payloadresolver.Store, tlogs map[string]tlog.Log, mirror *MirrorWiring, maxCredentialSize int, maxRetainChunkSize int, maxRetainPayloadSize int, mountIngest func(*http.ServeMux) error, readiness []ReadinessCheck, byRefHealthy func() bool, emitHealth *EmitHealthWiring) (http.Handler, error) {
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
	nodeDID := NodeDIDOf(chainCfg)
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
	// A report-mode network node (cmd/network) has no in-process by-reference
	// producer of its own, so instead of the global byRefHealthy gate above it
	// gates advertisement PER PUBLISHER by what that publisher has itself
	// reported via ReportEmitHealth (Task 10 D4). The two are mutually
	// exclusive — chainmanager.New panics if both are wired — so a caller must
	// never pass both a non-nil byRefHealthy AND a non-nil emitHealth.
	if emitHealth != nil {
		chainOpts = append(chainOpts, chainmanager.WithPublisherHealth(
			func(publisherDID string) emithealth.HealthState {
				return emitHealth.Store.State(publisherDID, time.Now())
			},
			emitHealth.AdvertiseWithoutReports,
		))
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
		return nil, fmt.Errorf("netcompose: chain peer verifier: %w", err)
	}

	authz := connect.WithInterceptors(auth.Interceptors(verifier)...)

	// RegisterEvidence's admission gate (D1): the head variant id (the exact
	// wire bytes StoreVC admitted — audit.proto's head_variant_address
	// documents the WIRE variant, not a body content address, since a
	// registering caller only ever holds StoreVCResult.WireVariantID, never a
	// body address to pair with it) must already be admitted in the local VC
	// store (StoreVC first), else the handler reports FailedPrecondition —
	// the arbitrary-hash amplification guard. ResolveVariantBody is the
	// narrowest local-store read that both proves admission of those exact
	// bytes AND resolves the body address EvidenceService.Register keys its
	// receipt/queue writes by (parity with pipeline/runtime's own
	// emissionRegistrar and the audit Runner, both already
	// body-address-keyed) — see its doc for why ResolveVariant's own
	// (bodyAddress, wireVariantID) signature cannot serve this directly.
	auditAdmitted := func(ctx context.Context, headVariantID string) (string, bool, error) {
		bodyAddress, err := vcSvc.ResolveVariantBody(ctx, headVariantID)
		if err != nil {
			if errors.Is(err, vcresolver.ErrNotFound) {
				return "", false, nil
			}
			return "", false, err
		}
		return bodyAddress, true, nil
	}
	auditEvidence := auditor.NewEvidenceService(auditReceipts, auditQueue, auditAdmitted)

	// Per-RPC inbound read caps: connect reads and DECOMPRESSES the request
	// body before the auth interceptor runs, and readMaxBytes=0 (the default)
	// is unlimited — so an unauthenticated compressed body could inflate to
	// exhaust memory. Cap every service to its message class (a send cap is
	// deliberately NOT set: list RPCs return unpaginated, legitimately large
	// responses). The outer MaxBytesHandler in main bounds the raw body /
	// h2c-upgrade path on top of these.
	proofCap := connect.WithReadMaxBytes(maxProofRequestBytes)
	docCap := connect.WithReadMaxBytes(maxDocumentRequestBytes)
	// ReportEmitHealth is mounted on the operator surface only when emitHealth
	// is wired (cmd/network); a caller with no report-mode consumer for this
	// RPC leaves OperatorHandler's implementation Unimplemented. peerVerifier
	// (built above for the L2 surfaces) is reused: ReportEmitHealth is "L1 +
	// wireauth", so it needs the SAME DID-resolution + nonce-store
	// infrastructure.
	chainOperatorOpts := []chainhandler.OperatorOption{
		chainhandler.WithSubscriber(chainSvc),
		chainhandler.WithAllowListReader(chainSvc),
	}
	if emitHealth != nil {
		chainOperatorOpts = append(chainOperatorOpts, chainhandler.WithEmitHealth(emitHealth.Store, peerVerifier, chainCfg.EmitHealth.TTL))
	}
	// retainChunkCap is PayloadStoreService's per-RPC class: sized to the
	// configured max-retain-chunk-size (not a fixed constant like proof/doc,
	// since a retained chunk's legitimate size is an operator-tunable quota,
	// same posture as the credential class above).
	retainChunkCap := connect.WithReadMaxBytes(maxRetainChunkSize)

	// tlogSvc is the read (+ D-T4 mirror-custody, when wired) service behind
	// TlogService: the static map always, plus — when mirror is non-nil —
	// the durable mirror store as a second read source and the D-T3
	// identity-enforcement deps MirrorLogSegment needs, reusing the SAME
	// resolver/DID-registry infra every other wireauth-checked RPC above
	// shares (resolver, didSvc, ed25519.Verifier{}).
	var tlogSvc *tlogservice.Service
	if mirror != nil {
		tlogSvc = tlogservice.New(tlogs, &tlogservice.MirrorConfig{
			Store:           mirror.Store,
			DIDResolver:     resolver,
			Ancestry:        logident.NewDIDRegistryAncestry(didSvc),
			Crypto:          ed25519.Verifier{},
			MaxBatchRecords: mirror.MaxBatchRecords,
			MaxBatchBytes:   mirror.MaxBatchBytes,
		})
	} else {
		tlogSvc = tlogservice.New(tlogs, nil)
	}
	// peerVerifier is reused for MirrorLogSegment's in-band wireauth proof —
	// same DID-resolution + nonce-store infra as the L2-only surfaces below.
	tlogHandlerImpl := tloghandler.New(tlogSvc, peerVerifier)

	mux := http.NewServeMux()
	for _, p := range []handlerPair{
		// schema bodies, DID docs/delegations, and full-replacement allowlists
		// can exceed the proof cap → document class.
		newPair(schemapbconnect.NewSchemaServiceHandler(schemahandler.New(schemaSvc), authz, docCap)),
		newPair(didpbconnect.NewDIDServiceHandler(didhandler.New(didSvc), authz, docCap)),
		// SignRequest.data can be a canonicalized credential, so it shares the
		// credential class (the config value StoreVC uses) — not the fixed doc
		// constant, or the two would diverge when max-credential-size is raised.
		newPair(signerpbconnect.NewSignerServiceHandler(signerhandler.New(signerSvc), authz, connect.WithReadMaxBytes(maxCredentialSize))),
		newPair(vcpbconnect.NewVCResolverServiceHandler(vchandler.New(vcSvc), authz, connect.WithReadMaxBytes(maxCredentialSize))),
		// Read-mostly / small-request control surfaces → proof class. (When a
		// mirror store is wired, MirrorLogSegment's OWN procedure path is
		// additionally overridden below at its own derived cap — see that
		// comment for why this mount stays unconditional and unchanged.)
		newPair(auditpbconnect.NewAuditServiceHandler(audithandler.New(auditor.NewStatusService(auditStatus, auditReceipts), auditEvidence, peerVerifier), authz, proofCap)),
		newPair(tlogpbconnect.NewTlogServiceHandler(tlogHandlerImpl, authz, proofCap)),
		newPair(chainpbconnect.NewChainServiceHandler(chainhandler.NewOperator(chainSvc, chainOperatorOpts...), authz, docCap)),
		// PayloadStoreService (RetainPayload) is the L1-gated write side of
		// by-reference payload delivery (unlike PayloadService below, mounted
		// with NO L1 interceptor): the authz interceptor decides whether the
		// caller may retain payloads at all, and storehandler additionally
		// verifies the in-band wireauth proof carried in the first frame,
		// requiring owner_did to equal the proven signer DID. peerVerifier is
		// reused (same DID-resolution + nonce-store infra as the L2-only
		// surfaces below).
		newPair(payloadpbconnect.NewPayloadStoreServiceHandler(storehandler.New(payloadStore, peerVerifier, uint64(maxRetainPayloadSize)), authz, retainChunkCap)),
	} {
		mux.Handle(p.path, p.h)
	}

	// WHEN a mirror store is wired, MirrorLogSegment needs a WIDER read cap
	// than proofCap: mirrored sink-receipt segments can carry full
	// credentials and a whole batch of records (up to
	// tlog-mirror.max-batch-bytes). The cap is DERIVED from max-batch-bytes
	// (mirrorReadCapBytes), not borrowed from maxCredentialSize — the two
	// config values govern unrelated classes (single-VC StoreVC/fetch vs.
	// this batch), and pinning the mount to a plain maxCredentialSize would
	// silently reject a legitimate batch whenever max-batch-bytes is
	// configured above it (Task 5 review, M-1: this WAS a real gap against
	// the repo's own shipped defaults — max-credential-size 1 MiB <
	// max-batch-bytes 4 MiB). Rather than restructure
	// NewTlogServiceHandler's uniform per-service option (it applies ONE
	// set of connect.HandlerOptions to every RPC it mounts), this overrides
	// the ONE procedure path with its own connect.NewUnaryHandler at the
	// derived cap: net/http's ServeMux resolves the more specific exact
	// pattern ("…/MirrorLogSegment") over the subtree pattern
	// ("…/TlogService/") registered above, REGARDLESS of registration order
	// (longest/most-specific pattern wins — the documented
	// net/http.ServeMux precedence rule), so the other three TlogService
	// RPCs stay on proofCap. A caller with mirror == nil registers no
	// override: MirrorLogSegment there still routes through the subtree
	// handler at proofCap.
	if mirror != nil {
		mirrorMethod := tlogpb.File_dplaax_tlog_v1_tlog_proto.Services().ByName("TlogService").Methods().ByName("MirrorLogSegment")
		mirrorHandler := connect.NewUnaryHandler(
			tlogpbconnect.TlogServiceMirrorLogSegmentProcedure,
			tlogHandlerImpl.MirrorLogSegment,
			connect.WithSchema(mirrorMethod),
			connect.WithHandlerOptions(authz, connect.WithReadMaxBytes(mirrorReadCapBytes(mirror.MaxBatchBytes))),
		)
		mux.Handle(tlogpbconnect.TlogServiceMirrorLogSegmentProcedure, mirrorHandler)
	}

	// Durable relationship-evidence log (transfer.relationship.record): each
	// verified RegisterSubscription/Disconnect snapshots the counterparty-signed
	// request + verifying key material under the chain root. Mirrors the sink
	// reject log — no checkpoint signer (the retained records already carry the
	// counterparty signature, not a signed log head).
	evFilelog, err := filelog.New(filepath.Join(chainRoot, "relationship-evidence"))
	if err != nil {
		return nil, fmt.Errorf("netcompose: chain relationship evidence log: %w", err)
	}
	evLog := evidence.New(evFilelog)

	// ChainPeerService is the internet-facing L2 surface: mounted WITHOUT the L1
	// authz interceptor (its trust is the per-RPC wireauth proof, slice-11). The
	// read cap matters MORE here than on L1 surfaces: there is no interceptor to
	// bound the request first, and the requests are small proofs + fields.
	peerPath, peerHandler := chainpbconnect.NewChainPeerServiceHandler(chainhandler.NewPeerWithEvidence(chainSvc, peerVerifier, evLog), proofCap)
	mux.Handle(peerPath, peerHandler)

	// PayloadService is the internet-facing L2 by-reference payload serving
	// boundary: same wireauth proof + allow-list admission (chainSvc.Admit) as the
	// chain peer surface, likewise no L1 interceptor. A ResolvePayload REQUEST is
	// just a content hash + proof (responses stream, unbounded by this). The
	// ServingBoundary authorizes on owner metadata BEFORE reading the bytes and
	// collapses a not-admitted caller to NotFound (F9/F4 — no existence oracle).
	payloadServing := payloadresolver.NewServingBoundary(payloadSvc, chainSvc)
	payloadPath, payloadHandler := payloadpbconnect.NewPayloadServiceHandler(payloadhandler.New(payloadServing, peerVerifier), proofCap)
	mux.Handle(payloadPath, payloadHandler)

	// Public, unauthenticated routes: W3C DID resolution (open read, slice-4),
	// liveness, and readiness. These deliberately carry no authz interceptor.
	// /healthz stays STATIC (liveness: "restart me if this fails");
	// /readyz is dependency-aware (readiness: "route no new work here") —
	// the checks are assembled by main from what this node is configured with.
	// Cached (ReadinessCacheTTL) so a /readyz flood cannot amplify into a
	// per-request outbound PDP probe (adversarial-review F7).
	mux.Handle("/did/", didhandler.NewResolutionHandler(didSvc, regCfg.ID))
	mux.HandleFunc("/healthz", healthz)
	mux.HandleFunc("/readyz", NewCachedReadiness(readiness, ReadinessCacheTTL).Handler())

	// HTTP push ingest (apipush) for push-enabled source loops: /ingest/<loop>/push
	// (PDP-guarded) and /ingest/<loop>/health (public). nil mounts nothing.
	if mountIngest != nil {
		if err := mountIngest(mux); err != nil {
			return nil, err
		}
	}

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
