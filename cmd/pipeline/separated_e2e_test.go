package main

// PR3b Task 9: THE separated-topology proof. A REAL netcompose.BuildHandler
// registry (mem/tmp stores, behind an httptest server) and a REAL cmd/pipeline
// composition (buildDeps + pipelineRuntimeConfigFrom + pipelineruntime.Build +
// buildShippers — the exact wiring main.go uses) talk ONLY over the wire: no
// shared Go objects, no in-process shortcuts. This is the first end-to-end
// evidence that the network/pipeline severance (AGENTS.md layer rule 2) still
// composes into a working node when the two halves run as separate processes
// would.
//
// Identity plumbing (the bulk of this file's setup) exists because a
// wireauth-protected registry call requires the CALLER's DID to resolve to a
// real key, and BuildHandler's own DID resolver is a concrete
// *didresolver.Resolver (an HTTP-fetching type, not swappable for a fake) —
// unlike the pipeline's OWN upstream-credential verifier (deps.Resolver),
// which is the resolver.Resolver INTERFACE and so happily takes
// resolver/local's in-memory fake, matching every other e2e test in this
// repo (cmd/standalone's aggregate_e2e_test.go, crossnode_e2e_test.go, etc).
// Two independent identity surfaces are therefore built:
//
//  1. A small stand-in HTTP DID-resolution server (newSepFakeDIDServer),
//     mapped via didresolver.WithRegistryBaseURL — this is what the registry
//     resolves EVERY wireauth caller's signer_did against (RegisterAuditHead
//     as the node identity, RegisterEvidence as the aggregate's issuer, and
//     MirrorLogSegment's checkpoint-signature check for every custody log).
//  2. For each producing loop's OWN emission log (src1's and, since the D9
//     update below, agg's too), the registry's OWN internal DID store
//     (network/pkg/services/didregistry/store/yamlstore) is seeded directly,
//     bypassing its RPC surface entirely: MirrorLogSegment's D-T3 "emission"
//     writer-binding check
//     (network/pkg/services/tlogservice/logident.AncestorPipeline) resolves
//     the checkpoint signer through the registry's OWN in-process
//     didregistry.Service, not through BuildHandler's outbound resolver —
//     and that service's RPC surface cannot register a self-controlled
//     process DID under CALLER-held keys (RegisterOwner requires owner
//     shape; IssueProcess mints its OWN custodial key pair, incompatible
//     with this node's local-keystore signing model). Seeding the same
//     on-disk store BuildHandler will open (via the exported
//     yamlstore.Store.SaveProcess, a legitimate Go API, not a production
//     code change) is the cheapest honest way to prove this path rather than
//     skipping it.
//
// See the report (.superpowers/sdd/task-9-cmdpipeline-report.md) for the full
// per-case assertion map and this identity analysis in more detail.
//
// D9 update: the main scenario originally had to split src1 and agg (two
// producing loops with different output subjects) across TWO separate
// runtimes/node identities, working around a real production gap this task
// discovered in buildDeps' payload-retain wiring (see the report's "Fix"
// section for the full analysis). That gap is now fixed
// (payloadClientFactory, wiring.go signs each RetainPayload call as the
// OWNING loop's own output subject), so the main scenario below runs all
// four loops — src1, sink1, archive, agg — on ONE runtime, and doubles as
// that fix's own end-to-end proof.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/nats-io/nkeys"
	"github.com/o3co/protobuf.interceptors/endpoint"

	auditpb "github.com/provin-line/oss/gen/go/dplaax/audit/v1"
	"github.com/provin-line/oss/gen/go/dplaax/audit/v1/auditpbconnect"
	vcpb "github.com/provin-line/oss/gen/go/dplaax/vc/v1"
	"github.com/provin-line/oss/gen/go/dplaax/vc/v1/vcpbconnect"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/internal/netcompose"
	"github.com/provin-line/oss/keystore"
	ksfilestore "github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/didresolver"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/network/pkg/registry"
	"github.com/provin-line/oss/network/pkg/services/auditor"
	didyaml "github.com/provin-line/oss/network/pkg/services/didregistry/store/yamlstore"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver"
	payloadmemstore "github.com/provin-line/oss/network/pkg/services/payloadresolver/memstore"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry"
	schemayaml "github.com/provin-line/oss/network/pkg/services/schemaregistry/store/yamlstore"
	tlogserviceclient "github.com/provin-line/oss/network/pkg/services/tlogservice/client"
	"github.com/provin-line/oss/network/pkg/services/tlogservice/mirrorstore"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/provenance/vcdid"
	pipelineruntime "github.com/provin-line/oss/pipeline/runtime"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	natstransport "github.com/provin-line/oss/pipeline/transport/nats"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/vc"
)

// ─────────────────────────────────────────────────────────────────────────
// Identities. registry component "reg" + accountType "org" matches every
// other e2e test in this repo (cmd/standalone's crossnode_e2e_test.go etc).
// ─────────────────────────────────────────────────────────────────────────

const (
	sepRegistryID = "reg"
	sepBearer     = "sep-test-bearer"

	sepOwnerDID = "did:dplaax:reg:org:acme"

	// sepSrc1IssuerDID is a REAL, running source loop's signing identity: its
	// FirstDrops are verified downstream (sink1, archive) via resolver/local,
	// and its emission log's checkpoint is verified by the registry both for
	// its signature (the fake DID server) and its D-T3 emission ancestry (the
	// registry's own internal DID store, seeded directly — see the file doc).
	sepSrc1IssuerDID = "did:dplaax:reg:org:acme:pipeline:src1:process:s1"
	sepSrc1Pipeline  = "did:dplaax:reg:org:acme:pipeline:src1"
	sepSrc1Ingress   = "ingest.sep.src1"

	// sepAggIssuerDID signs the aggregate's own emitted FirstDrop and is the
	// registrantDID RegisterEvidence proves (wireReceiptWriter.Put).
	sepAggIssuerDID = "did:dplaax:reg:org:acme:pipeline:aggout:process:a1"
	sepAggPipeline  = "did:dplaax:reg:org:acme:pipeline:aggout"

	// sepAggSrcA/BIssuerDID are the aggregate's two ingress feeds. They are
	// NOT run by a live source loop — they are pre-signed once (like
	// cmd/standalone/aggregate_e2e_test.go's signedSourceEnv) and republished
	// verbatim on retry, so a retry can never fork into a THIRD distinct
	// source the aggregate's dedup would need to fold in.
	sepAggSrcAIssuerDID = "did:dplaax:reg:org:acme:pipeline:aggsrca:process:sa"
	sepAggSrcAPipeline  = "did:dplaax:reg:org:acme:pipeline:aggsrca"
	sepAggSrcBIssuerDID = "did:dplaax:reg:org:acme:pipeline:aggsrcb:process:sb"
	sepAggSrcBPipeline  = "did:dplaax:reg:org:acme:pipeline:aggsrcb"

	// sepArchiveIssuerDID signs the archival sink's provin:sink-receipt
	// credentials and checkpoints its dedicated receipt log (KindSinkReceipt
	// — direct signer==owner equality, no registry-internal ancestry needed).
	sepArchiveIssuerDID = "did:dplaax:reg:org:acme:pipeline:archive:process:r1"
)

// ─────────────────────────────────────────────────────────────────────────
// DID document construction. Three different shapes for three different
// consumers of "the same" identity — see the file doc for why they differ.
// ─────────────────────────────────────────────────────────────────────────

// sepIdentityDoc is what the FAKE DID SERVER serves for a wireauth-calling
// identity: a Multikey "#signing" key under AssertionMethod (checkpoint
// signature verification, tlogservice.verifyMirrorIdentity step 1) plus a
// JsonWebKey2020 "#auth" key under Authentication (the wireauth PROOF wrapping
// RegisterAuditHead/RegisterEvidence/MirrorLogSegment itself — mirrors
// wiring_test.go's authDoc, which this file reuses for the raw jwk() helper).
func sepIdentityDoc(t *testing.T, subject string, pub []byte) *did.DIDDocument {
	t.Helper()
	signVM, err := did.NewMultikeyVerificationMethod(subject+"#signing", subject, pub)
	if err != nil {
		t.Fatalf("sepIdentityDoc %q: %v", subject, err)
	}
	return did.New(did.DocumentFields{
		Context:    did.IssuedDocumentContexts(),
		ID:         subject,
		Controller: subject,
		VerificationMethod: []did.VerificationMethod{
			signVM,
			{ID: subject + "#auth", Type: "JsonWebKey2020", Controller: subject, PublicKeyJWK: jwk(pub)},
		},
		AssertionMethod: []string{subject + "#signing"},
		Authentication:  []string{subject + "#auth"},
	})
}

// sepLocalProcessDoc is what resolver/local serves the PIPELINE's own
// upstream-credential verifier (vc.Verifier's evalChainConsistency): a
// Multikey "#signing" AssertionMethod key, Controller set to owner directly
// (a 1-hop process->owner walk, the same convention capProcessDoc/capOwnerDoc
// use in cmd/standalone's own e2e tests).
func sepLocalProcessDoc(t *testing.T, processDID, owner string, pub []byte) *did.DIDDocument {
	t.Helper()
	vm, err := did.NewMultikeyVerificationMethod(processDID+"#signing", processDID, pub)
	if err != nil {
		t.Fatalf("sepLocalProcessDoc %q: %v", processDID, err)
	}
	return did.New(did.DocumentFields{
		Context:            did.IssuedDocumentContexts(),
		ID:                 processDID,
		Controller:         owner,
		VerificationMethod: []did.VerificationMethod{vm},
		AssertionMethod:    []string{processDID + "#signing"},
	})
}

func sepOwnerDocLocal(owner string) *did.DIDDocument {
	return did.New(did.DocumentFields{ID: owner, Controller: owner})
}

// sepInternalProcessDoc is what the REGISTRY's OWN internal DID store
// (didyaml, seeded directly — see the file doc) serves for
// logident.AncestorPipeline's read: Controller MUST be the pipeline DID
// (2-segment resource path), not the owner — AncestorPipeline only checks
// that this document's Controller() parses as a pipeline DID and compares it
// to the emission log's own owner, it never separately resolves that
// pipeline DID's own document.
func sepInternalProcessDoc(t *testing.T, processDID, pipelineDID string, pub []byte) *did.DIDDocument {
	t.Helper()
	vm, err := did.NewMultikeyVerificationMethod(processDID+"#signing", processDID, pub)
	if err != nil {
		t.Fatalf("sepInternalProcessDoc %q: %v", processDID, err)
	}
	return did.New(did.DocumentFields{
		Context:            did.IssuedDocumentContexts(),
		ID:                 processDID,
		Controller:         pipelineDID,
		VerificationMethod: []did.VerificationMethod{vm},
		AssertionMethod:    []string{processDID + "#signing"},
	})
}

// sepDIDPath mirrors network/pkg/didresolver.Resolver.resolutionURL's own
// path construction exactly: {base}/did/{accountType}/{accountId}/{resourcePath...}/did.json.
func sepDIDPath(t *testing.T, didStr string) string {
	t.Helper()
	d, err := dplaax.Parse(didStr)
	if err != nil {
		t.Fatalf("sepDIDPath parse %q: %v", didStr, err)
	}
	segs := append([]string{d.AccountType, d.AccountID}, d.ResourcePath...)
	return "/did/" + strings.Join(segs, "/") + "/did.json"
}

// newSepFakeDIDServer stands up the minimal stand-in resolution service every
// wireauth-calling identity in this file resolves against (see the file
// doc's identity-plumbing analysis for why a full second netcompose registry
// is not used here).
func newSepFakeDIDServer(t *testing.T, docs map[string]*did.DIDDocument) string {
	t.Helper()
	mux := http.NewServeMux()
	for didStr, doc := range docs {
		b, err := doc.MarshalJSON()
		if err != nil {
			t.Fatalf("newSepFakeDIDServer marshal %q: %v", didStr, err)
		}
		body := b
		mux.HandleFunc(sepDIDPath(t, didStr), func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/did+json")
			_, _ = w.Write(body)
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// ─────────────────────────────────────────────────────────────────────────
// Registry construction: netcompose.BuildHandler over mem/tmp stores, behind
// an httptest server — mirrors internal/netcompose/server_test.go's own
// assembledHandlerWith harness (this file's template, reconstructed here
// since that helper is unexported to a different package).
// ─────────────────────────────────────────────────────────────────────────

func sepChainCfg(t *testing.T) *chainconfig.Config {
	t.Helper()
	acc, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	accSeed, err := acc.Seed()
	if err != nil {
		t.Fatal(err)
	}
	op, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal(err)
	}
	opSeed, err := op.Seed()
	if err != nil {
		t.Fatal(err)
	}
	return &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS: chainconfig.NATSConfig{
			URL:           "nats://unused-in-e2e:4222",
			AccountSeed:   string(accSeed),
			TrustRootSeed: string(opSeed),
			ResolverDir:   t.TempDir(),
			NodeDID:       "did:dplaax:" + sepRegistryID + ":org:registry-node",
		},
	}
}

// sepRegistryHandle is the running registry's URL plus the raw in-memory
// audit stores this test reads directly (the "queue store directly" seam the
// task brief names as an acceptable read for the ordinary-ingress/sink-receipt
// cases, alongside the wire ResolveVC/GetConsumedSources reads used elsewhere).
type sepRegistryHandle struct {
	url        string
	auditQueue *auditor.MemQueue
}

// buildSepRegistry assembles the full production mux (netcompose.BuildHandler)
// over mem/tmp stores. fakeDIDURL is where the registry's OWN outbound
// resolver sends every DID resolution (every wireauth caller in this file).
// seedProcesses, when non-empty, pre-seeds the registry's OWN internal DID
// store directly (see the file doc) BEFORE BuildHandler opens the same
// directory. wrap, when non-nil, wraps the assembled handler (the shutdown-
// fault case's slow-registry middleware).
func buildSepRegistry(t *testing.T, fakeDIDURL string, seedProcesses map[string]*did.DIDDocument, wrap func(http.Handler) http.Handler) sepRegistryHandle {
	t.Helper()
	dataDir := t.TempDir()
	if len(seedProcesses) > 0 {
		st := didyaml.New(filepath.Join(dataDir, "dids"))
		for didStr, doc := range seedProcesses {
			d, err := dplaax.Parse(didStr)
			if err != nil {
				t.Fatalf("buildSepRegistry: parse seed DID %q: %v", didStr, err)
			}
			if err := st.SaveProcess(d, doc, nil); err != nil {
				t.Fatalf("buildSepRegistry: seed internal DID store for %q: %v", didStr, err)
			}
		}
	}

	coreCfg := &core.CoreConfig{DataDir: dataDir, ListenAddr: ":0", AllowLoopback: true}
	regCfg := &registry.RegistryConfig{ID: sepRegistryID}
	verifier := endpoint.NewStaticEndpoint([]endpoint.StaticRule{
		{Resource: "vc", Action: "store"},
		{Resource: "vc", Action: "read"},
		{Resource: "audit", Action: "register"},
		{Resource: "audit", Action: "read"},
		{Resource: "tlog", Action: "mirror"},
		{Resource: "tlog", Action: "read"},
		// buildDeps (wiring.go) ALWAYS wires a PayloadStore — every producing
		// loop dual-emits (D-6) — so RetainPayload is exercised regardless of
		// this scenario's config never declaring payload-delivery.
		{Resource: "payloads", Action: "retain"},
	})
	chainCfg := sepChainCfg(t)
	guard := core.NewURLGuard(core.WithAllowLoopback(true))
	resolver := didresolver.New(guard, didresolver.WithRegistryBaseURL(func(reg string) (string, error) {
		if reg == sepRegistryID {
			return fakeDIDURL, nil
		}
		return "", fmt.Errorf("sep: unmapped registry %q", reg)
	}))
	vcSvc := vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), memstore.NewPool())
	chainOp, err := netcompose.ChainOperator(chainCfg)
	if err != nil {
		t.Fatalf("buildSepRegistry: ChainOperator: %v", err)
	}
	schemaSvc := schemaregistry.New(schemayaml.New(t.TempDir()))
	payloadStore := payloadmemstore.New()
	mStore, err := mirrorstore.Open(t.TempDir())
	if err != nil {
		t.Fatalf("buildSepRegistry: mirrorstore.Open: %v", err)
	}
	mirror := &netcompose.MirrorWiring{Store: mStore, MaxBatchRecords: 256, MaxBatchBytes: 4 << 20}
	auditQueue := auditor.NewMemQueue()
	auditStatus := auditor.NewMemStatusStore()
	auditReceipts := auditor.NewMemReceiptStore()

	h, err := netcompose.BuildHandler(coreCfg, regCfg, chainCfg, chainOp, verifier, guard, resolver, vcSvc,
		auditStatus, auditReceipts, auditQueue, schemaSvc, payloadresolver.New(payloadStore), payloadStore,
		map[string]tlog.Log{}, mirror, 1<<20, 1<<20, 64<<20, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("buildSepRegistry: BuildHandler: %v", err)
	}
	var handler http.Handler = h
	if wrap != nil {
		handler = wrap(handler)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return sepRegistryHandle{url: srv.URL, auditQueue: auditQueue}
}

// ─────────────────────────────────────────────────────────────────────────
// Small polling / signing helpers.
// ─────────────────────────────────────────────────────────────────────────

// sepRetryUntil calls action immediately, then again on every tick, until
// done reports true or deadline elapses — the "loops subscribe
// asynchronously; re-push until delivered" idiom every e2e test in this repo
// uses for NATS core's pre-subscription message drop.
func sepRetryUntil(t *testing.T, deadline, tick time.Duration, action func(), done func() bool) {
	t.Helper()
	action()
	if done() {
		return
	}
	dl := time.After(deadline)
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			action()
			if done() {
				return
			}
		case <-dl:
			t.Fatal("sep: condition not met before deadline")
		}
	}
}

func sepPayloadHash(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// sepSignFeed signs a real source FirstDrop (issuer's key already saved in
// builder's keystore) and returns the credential plus its inline wire
// envelope — mirrors cmd/standalone/aggregate_e2e_test.go's signedSourceEnv.
func sepSignFeed(t *testing.T, builder *vc.Builder, issuerDID, procID string, payload []byte) (*vc.PipelinePassCredential, []byte) {
	t.Helper()
	s, err := vcdid.NewSigner(vcdid.Config{
		Builder: builder, IssuerDID: issuerDID, KeyID: string(keystore.KeyIDSigning),
		VerificationMethod: issuerDID + "#signing", PipelineID: procID, ProcessID: procID,
		TransformationClaim: vc.ClaimConvert,
	})
	if err != nil {
		t.Fatalf("sepSignFeed signer %q: %v", issuerDID, err)
	}
	h := sepPayloadHash(payload)
	cred, err := s.SignFirstDrop(context.Background(), payload, h, h)
	if err != nil {
		t.Fatalf("sepSignFeed SignFirstDrop %q: %v", issuerDID, err)
	}
	wire, err := envelopecodec.New().MarshalEnvelope(&contract.Envelope{Credential: cred, Payload: payload, SequenceNo: 1})
	if err != nil {
		t.Fatalf("sepSignFeed MarshalEnvelope %q: %v", issuerDID, err)
	}
	return cred, wire
}

// sepAwaitTwoSourceAggregate polls ch (the aggregate's observed output
// subject) publishing both pre-signed feeds until a TWO-source aggregate
// FirstDrop arrives — a tick mid-arrival may emit a transient one-source
// aggregate first (cmd/standalone/aggregate_e2e_test.go's own rationale).
func sepAwaitTwoSourceAggregate(t *testing.T, ch <-chan []byte, publishBoth func(), deadline time.Duration) *vc.PipelinePassCredential {
	t.Helper()
	codec := envelopecodec.New()
	publishBoth()
	dl := time.After(deadline)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case wire := <-ch:
			env, err := codec.UnmarshalEnvelope(wire)
			if err != nil {
				t.Fatalf("sepAwaitTwoSourceAggregate: decode: %v", err)
			}
			if env.Credential == nil {
				continue
			}
			if sc := env.Credential.SourceCommitment(); sc != nil && len(sc.DerivedFrom) == 2 {
				return env.Credential
			}
		case <-tick.C:
			publishBoth()
		case <-dl:
			t.Fatal("sep: no two-source aggregate FirstDrop was emitted")
		}
	}
}

// sepFindAuditedCredential retry-publishes (action) while polling the
// registry's audit queue (read directly — the task brief's "queue store
// directly" seam) and, for each candidate, resolving it over the WIRE
// (vcClient.ResolveVC) checking match. Used by both the ordinary-ingress and
// sink-receipt cases, which differ only in action/match.
func sepFindAuditedCredential(t *testing.T, ctx context.Context, queue *auditor.MemQueue, vcClient vcpbconnect.VCResolverServiceClient, action func(), match func(*vc.PipelinePassCredential) bool, deadline time.Duration) string {
	t.Helper()
	var found string
	sepRetryUntil(t, deadline, 200*time.Millisecond, action, func() bool {
		cands, err := queue.ListNewest(500)
		if err != nil {
			return false
		}
		for _, c := range cands {
			resp, rerr := vcClient.ResolveVC(ctx, connect.NewRequest(&vcpb.ResolveVCRequest{Hash: c.HeadHash}))
			if rerr != nil {
				continue
			}
			var cred vc.PipelinePassCredential
			if json.Unmarshal(resp.Msg.GetCredential(), &cred) != nil {
				continue
			}
			if match(&cred) {
				found = c.HeadHash
				return true
			}
		}
		return false
	})
	return found
}

// ─────────────────────────────────────────────────────────────────────────
// The main scenario: ONE registry + ONE pipeline RUNTIME (four loops: a real
// source, an observation-only sink, an archival sink with a receipt issuer,
// and an aggregate — src1 and agg are two producing loops with DIFFERENT
// output subjects, sharing this one runtime's keystore) over ONE embedded
// NATS broker — proving cases 1-4.
// ─────────────────────────────────────────────────────────────────────────

func TestSeparatedTopology_RegistryAndPipelineOverTheWire(t *testing.T) {
	ctx := context.Background()
	gen := ed25519.Generator{}

	// The pipeline's own keystore: holds every LIVE identity's keys (both node
	// identities, src1's producing issuer, the aggregate's issuer, the archival
	// sink's receipt issuer) — signing (#signing) and wireauth (#auth) share
	// one keypair per identity (two different key IDs, same key material; see
	// the file doc for why both are needed).
	ks := ksfilestore.New(t.TempDir())
	genIdentity := func(subjectDID string, signing bool) []byte {
		kp, err := gen.Generate()
		if err != nil {
			t.Fatalf("keygen %q: %v", subjectDID, err)
		}
		keys := map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: kp}
		if signing {
			keys[keystore.KeyIDSigning] = kp
		}
		if err := ks.SaveKeyPair(subjectDID, keys); err != nil {
			t.Fatalf("save key %q: %v", subjectDID, err)
		}
		return kp.PublicKey
	}
	// This node runs as ONE runtime with FOUR loops — src1 (source), sink1
	// (observation-only), archive (archival + receipt), and agg (aggregate) —
	// sharing ONE node identity and ONE keystore. src1 and agg are TWO
	// DIFFERENT producing loops with TWO DIFFERENT output subjects: exactly
	// the topology that used to be impossible on a single runtime before the
	// D9 fix (payloadClientFactory, wiring.go). PayloadStoreService's
	// RetainPayload requires owner_did (the emitting loop's OWN output
	// subject — dataplane.go's retainerFor(src.OutputSubject)) to equal the
	// proven signer (network/pkg/services/payloadresolver/storehandler's
	// errOwnerMismatch) — "a producing process retains its own emitted
	// payload" per that package's own retain_e2e_test.go — and buildDeps used
	// to wire ONE shared node-identity retain client for every producing
	// loop, which could satisfy at most ONE loop's output subject at a time
	// (this test used to run src1 and agg as two SEPARATE runtimes to work
	// around exactly that gap — see git history for the prior version, and
	// the task report's "Blocker discovered" section for the original
	// analysis). buildDeps now signs each retain call as the OWNING loop's
	// OWN output subject (payloadClientFactory.For(ownerDID), keyed per
	// call), so ONE runtime now suffices as long as the keystore holds BOTH
	// producing loops' output-subject keys — which this test already
	// provisions below (src1NodePub, aggNodePub) for an unrelated reason
	// (both are ALSO the wireauth caller identities each loop's own
	// emission-log mirror checkpoint signs as).
	src1NodePub := genIdentity(sepSrc1Pipeline, false)
	aggNodePub := genIdentity(sepAggPipeline, false)
	src1Pub := genIdentity(sepSrc1IssuerDID, true)
	aggPub := genIdentity(sepAggIssuerDID, true)
	archivePub := genIdentity(sepArchiveIssuerDID, true)

	// The aggregate's two feeds are pre-signed with a THROWAWAY keystore (they
	// are never run by a live loop in this node — see the file doc).
	aggSrcKS := ksfilestore.New(t.TempDir())
	aggSrcAKP, err := gen.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := aggSrcKS.SaveKeyPair(sepAggSrcAIssuerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: aggSrcAKP}); err != nil {
		t.Fatal(err)
	}
	aggSrcBKP, err := gen.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := aggSrcKS.SaveKeyPair(sepAggSrcBIssuerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: aggSrcBKP}); err != nil {
		t.Fatal(err)
	}

	// The pipeline's OWN upstream-credential verifier (deps.Resolver): a
	// resolver.Resolver INTERFACE, so resolver/local's in-memory fake is the
	// cheapest honest choice here (matches every other e2e test in this repo).
	localResolver := local.New()
	localResolver.Add(sepOwnerDocLocal(sepOwnerDID))
	localResolver.Add(sepLocalProcessDoc(t, sepSrc1IssuerDID, sepOwnerDID, src1Pub))
	localResolver.Add(sepLocalProcessDoc(t, sepAggSrcAIssuerDID, sepOwnerDID, aggSrcAKP.PublicKey))
	localResolver.Add(sepLocalProcessDoc(t, sepAggSrcBIssuerDID, sepOwnerDID, aggSrcBKP.PublicKey))

	// The registry's outbound DID resolution target: every wireauth caller in
	// this scenario (both node identities, src1, agg, archive).
	fakeDIDURL := newSepFakeDIDServer(t, map[string]*did.DIDDocument{
		sepSrc1Pipeline:     sepIdentityDoc(t, sepSrc1Pipeline, src1NodePub),
		sepAggPipeline:      sepIdentityDoc(t, sepAggPipeline, aggNodePub),
		sepSrc1IssuerDID:    sepIdentityDoc(t, sepSrc1IssuerDID, src1Pub),
		sepAggIssuerDID:     sepIdentityDoc(t, sepAggIssuerDID, aggPub),
		sepArchiveIssuerDID: sepIdentityDoc(t, sepArchiveIssuerDID, archivePub),
	})

	// The registry itself, with src1's AND agg's process DIDs pre-seeded into
	// its OWN internal DID store (emission-log mirror custody's D-T3 ancestry
	// check — see the file doc): both are producing loops whose emission log
	// classifies as logident.KindEmission, which resolves its checkpoint
	// signer's ancestor pipeline through this internal store, not the fake
	// external DID server (archive's receipt log is the one exception —
	// KindSinkReceipt needs no such seeding, see the file doc).
	reg := buildSepRegistry(t, fakeDIDURL, map[string]*did.DIDDocument{
		sepSrc1IssuerDID: sepInternalProcessDoc(t, sepSrc1IssuerDID, sepSrc1Pipeline, src1Pub),
		sepAggIssuerDID:  sepInternalProcessDoc(t, sepAggIssuerDID, sepAggPipeline, aggPub),
	}, nil)

	// ONE pipeline config, FOUR loops: src1 (source), sink1 (observation-only
	// consumer), archive (archival sink + receipt issuer), and agg
	// (aggregate) — src1 and agg are the two producing loops with DIFFERENT
	// output subjects the D9 fix (see this function's own doc, above) makes
	// coexist on a single runtime.
	pipeCfg := &pipelineconfig.Config{
		VCStoreEndpoint:   reg.url,
		VCStoreBearer:     sepBearer,
		MaxCredentialSize: 1 << 20,
		TlogMirror:        pipelineconfig.TlogMirrorConfig{MaxBatchRecords: 256, MaxBatchBytes: 4 << 20, FlushInterval: time.Hour},
		Loops: []pipelineconfig.LoopConfig{
			{
				Name: "src1", Role: pipelineconfig.RoleSource, IngressSubject: sepSrc1Ingress,
				Source: pipelineconfig.SourceConfig{
					OutputSubject: sepSrc1Pipeline,
					Issuer:        pipelineconfig.IssuerConfig{DID: sepSrc1IssuerDID, KeyID: string(keystore.KeyIDSigning), VerificationMethod: sepSrc1IssuerDID + "#signing"},
					PipelineID:    "src1", ProcessID: "s1", TransformationClaim: vc.ClaimConvert,
				},
			},
			{
				Name: "sink1", Role: pipelineconfig.RoleSink, IngressSubject: sepSrc1Pipeline,
				Sink: pipelineconfig.SinkConfig{Kind: pipelineconfig.SinkObservationOnly, VerificationStrategy: pipelineconfig.StrategyAdjacent, UpstreamEndpoint: "https://sep.example/src1"},
			},
			{
				Name: "archive", Role: pipelineconfig.RoleSink, IngressSubject: sepSrc1Pipeline,
				Sink: pipelineconfig.SinkConfig{
					Kind: pipelineconfig.SinkArchival, VerificationStrategy: pipelineconfig.StrategyAdjacent, UpstreamEndpoint: "https://sep.example/src1",
					Receipt: pipelineconfig.SinkReceiptConfig{
						Issue:      true,
						Issuer:     pipelineconfig.IssuerConfig{DID: sepArchiveIssuerDID, KeyID: string(keystore.KeyIDSigning), VerificationMethod: sepArchiveIssuerDID + "#signing"},
						PipelineID: "archive", ProcessID: "r1",
					},
				},
			},
			{
				Name: "agg", Role: pipelineconfig.RoleAggregate,
				Aggregate: pipelineconfig.AggregateConfig{
					OutputSubject: sepAggPipeline,
					Issuer:        pipelineconfig.IssuerConfig{DID: sepAggIssuerDID, KeyID: string(keystore.KeyIDSigning), VerificationMethod: sepAggIssuerDID + "#signing"},
					PipelineID:    "aggout", ProcessID: "a1",
					VerificationStrategy: pipelineconfig.StrategyAdjacent,
					Window:               100 * time.Millisecond,
					Ingresses: []pipelineconfig.AggregateIngress{
						{Subject: sepAggSrcAPipeline, UpstreamEndpoint: "https://sep.example/aggsrca"},
						{Subject: sepAggSrcBPipeline, UpstreamEndpoint: "https://sep.example/aggsrcb"},
					},
				},
			},
		},
	}

	natsURL := runEmbeddedNATS(t)
	acc, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	accSeed, err := acc.Seed()
	if err != nil {
		t.Fatal(err)
	}

	guard := core.NewURLGuard(core.WithAllowLoopback(true))

	buildRuntime := func(pipeCfg *pipelineconfig.Config, nodeDID, dataDirName string) *pipelineruntime.Runtime {
		t.Helper()
		chainCfg := &chainconfig.Config{
			Transport: chainconfig.TransportNATS,
			NATS:      chainconfig.NATSConfig{URL: natsURL, AccountSeed: string(accSeed), NodeDID: nodeDID},
		}
		rtCfg, rerr := pipelineRuntimeConfigFrom(chainCfg, pipeCfg, filepath.Join(t.TempDir(), dataDirName))
		if rerr != nil {
			t.Fatalf("pipelineRuntimeConfigFrom(%s): %v", dataDirName, rerr)
		}
		deps := buildDeps(pipeCfg, ks, guard, localResolver, nodeDID)
		dp, berr := pipelineruntime.Build(context.Background(), &rtCfg, ks, deps)
		if berr != nil {
			t.Fatalf("pipelineruntime.Build(%s): %v", dataDirName, berr)
		}
		t.Cleanup(func() { _ = dp.Close() })
		runCtx, cancel := context.WithCancel(context.Background())
		runDone := make(chan error, 1)
		go func() { runDone <- dp.Run(runCtx) }()
		t.Cleanup(func() { cancel(); <-runDone })
		return dp
	}
	// ONE runtime for all four loops. nodeDID (this runtime's own subscriber/
	// AuditQueue/PayloadResolver identity) can be ANY identity the keystore
	// already holds an #auth key for — it need not equal either producing
	// loop's own output subject any more (that was the pre-D9 constraint);
	// sepSrc1Pipeline is reused here only because its key already exists.
	dp := buildRuntime(pipeCfg, sepSrc1Pipeline, "a")

	inj, err := natstransport.Connect(context.Background(), natstransport.Config{URL: natsURL, AccountSeed: string(accSeed)})
	if err != nil {
		t.Fatalf("injector connect: %v", err)
	}
	t.Cleanup(func() { _ = inj.Close() })

	aggOut := make(chan []byte, 16)
	if err := inj.Subscriber(sepAggPipeline).Subscribe(func(b []byte) {
		select {
		case aggOut <- b:
		default:
		}
	}); err != nil {
		t.Fatalf("observe agg output: %v", err)
	}
	pubSrc1Ingress := inj.Publisher(sepSrc1Ingress)
	pubAggSrcA := inj.Publisher(sepAggSrcAPipeline)
	pubAggSrcB := inj.Publisher(sepAggSrcBPipeline)

	vcClient := vcpbconnect.NewVCResolverServiceClient(guard.HTTPClient(), reg.url, connect.WithInterceptors(bearerInterceptor(sepBearer)))
	auditClient := auditpbconnect.NewAuditServiceClient(guard.HTTPClient(), reg.url, connect.WithInterceptors(bearerInterceptor(sepBearer)))

	// ── Case 1: ordinary ingress — a source loop emits, a sink loop
	// consumes+verifies, the credential lands in the registry's VC store
	// (wire StoreVC) and its head is registered for linear audit
	// (RegisterAuditHead), asserted against the registry's OWN audit-queue
	// store plus a wire ResolveVC. ──
	t.Run("OrdinaryIngress_WireStoreVCAndRegisterAuditHead", func(t *testing.T) {
		hash := sepFindAuditedCredential(t, ctx, reg.auditQueue, vcClient, func() {
			_ = pubSrc1Ingress.Publish([]byte(`{"reading":1}`))
		}, func(cred *vc.PipelinePassCredential) bool {
			return cred.Issuer() == sepSrc1IssuerDID
		}, 15*time.Second)
		if hash == "" {
			t.Fatal("sep: no audited credential found for src1")
		}
	})

	// ── Case 2: aggregate consumed-set — the aggregate consumes its two
	// pre-signed feeds and emits; RegisterEvidence recorded the consumed-set
	// receipt on the registry, asserted via the wire GetConsumedSources RPC. ──
	t.Run("AggregateConsumedSet_WireRegisterEvidence", func(t *testing.T) {
		aggBuilder := vc.NewBuilder(aggSrcKS)
		credA, envA := sepSignFeed(t, aggBuilder, sepAggSrcAIssuerDID, "sa", []byte(`{"reading":10}`))
		credB, envB := sepSignFeed(t, aggBuilder, sepAggSrcBIssuerDID, "sb", []byte(`{"reading":20}`))
		hashA, err := credA.Hash()
		if err != nil {
			t.Fatal(err)
		}
		hashB, err := credB.Hash()
		if err != nil {
			t.Fatal(err)
		}

		aggCred := sepAwaitTwoSourceAggregate(t, aggOut, func() {
			_ = pubAggSrcA.Publish(envA)
			_ = pubAggSrcB.Publish(envB)
		}, 20*time.Second)
		aggHash, err := aggCred.Hash()
		if err != nil {
			t.Fatal(err)
		}

		resp, err := auditClient.GetConsumedSources(ctx, connect.NewRequest(&auditpb.GetConsumedSourcesRequest{HeadHash: aggHash, PageSize: 10}))
		if err != nil {
			t.Fatalf("GetConsumedSources(%s): %v", aggHash, err)
		}
		got := append([]string(nil), resp.Msg.GetConsumed()...)
		sort.Strings(got)
		want := []string{hashA, hashB}
		sort.Strings(want)
		if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
			t.Errorf("GetConsumedSources(%s) = %v, want %v", aggHash, got, want)
		}
	})

	// ── Case 3: sink receipt — the archival sink consumes src1's ingress and
	// issues a provin:sink-receipt credential: stored (wire StoreVC) + its
	// own head registered (RegisterAuditHead), asserted the same way case 1
	// is. ──
	t.Run("SinkReceipt_WireStoredAndAuditRegistered", func(t *testing.T) {
		match := func(cred *vc.PipelinePassCredential) bool {
			if cred.Issuer() != sepArchiveIssuerDID {
				return false
			}
			subj, err := cred.Subject()
			return err == nil && subj.TransformationClaim == vc.ClaimSinkReceipt
		}
		hash := sepFindAuditedCredential(t, ctx, reg.auditQueue, vcClient, func() {
			_ = pubSrc1Ingress.Publish([]byte(`{"reading":1}`))
		}, match, 15*time.Second)
		if hash == "" {
			t.Fatal("sep: no sink-receipt credential found")
		}
	})

	// ── Case 4: mirror custody LIVE — the shippers ship src1's emission log,
	// archive's receipt log, AND agg's emission log; GetMirrorState advances
	// to each local log's size. agg's own emission log is included here (not
	// just src1's and archive's, as before the D9 fix) precisely BECAUSE it
	// now shares this ONE runtime with src1: a nonempty local log for agg is
	// itself proof its retain succeeded — dataplane.go's payloadWiring
	// aborts an emission (and so never appends it to the emission log)
	// before it is ever broadcast when the retain call fails, per the task
	// report's own analysis. ──
	t.Run("MirrorCustody_LiveGetMirrorStateAdvances", func(t *testing.T) {
		var wanted []pipelineruntime.CustodyLog
		for _, c := range dp.CustodyLogs() {
			if c.LogID == sepSrc1Pipeline || c.LogID == "sink-receipt:"+sepArchiveIssuerDID || c.LogID == sepAggPipeline {
				wanted = append(wanted, c)
			}
		}
		if len(wanted) != 3 {
			t.Fatalf("custody logs matched = %d, want 3 (src1 emission + archive receipt + agg emission); all custody logs: %+v", len(wanted), dp.CustodyLogs())
		}

		mirrorFactory := newMirrorClientFactory(ks, reg.url, sepBearer, guard.HTTPClient())
		shippers, err := buildShippers(wanted, mirrorFactory.forClient, pipeCfg.TlogMirror)
		if err != nil {
			t.Fatalf("buildShippers: %v", err)
		}

		tlogClient := tlogserviceclient.New(tlogserviceclient.Config{BaseURL: reg.url, HTTPClient: guard.HTTPClient(), Bearer: sepBearer})
		// Cases 1-3's own retry-publish loops can leave a straggler NATS
		// message being processed (each retry signs a genuinely distinct
		// credential, unlike the rest of this repo's pre-signed-envelope
		// retries) — a record can land in the local log AFTER an earlier
		// Drain already shipped everything that existed at that moment. So
		// Drain and the size comparison are retried TOGETHER until they
		// converge, rather than assuming one Drain call is the last write.
		for i, c := range wanted {
			sh := shippers[i]
			var localSize, acked uint64
			sepRetryUntil(t, 15*time.Second, 300*time.Millisecond, func() {
				dctx, dcancel := context.WithTimeout(ctx, 10*time.Second)
				_ = sh.Drain(dctx)
				dcancel()
			}, func() bool {
				var serr, gerr error
				localSize, serr = c.Log.Size(ctx)
				if serr != nil {
					return false
				}
				acked, gerr = tlogClient.GetMirrorState(ctx, c.LogID)
				return gerr == nil && acked == localSize
			})
			if acked != localSize {
				t.Errorf("GetMirrorState(%q) = %d, want %d (the local log's size) — did not converge", c.LogID, acked, localSize)
			}
			if localSize == 0 {
				t.Errorf("local log %q is empty — nothing was actually mirrored", c.LogID)
			}
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────
// Case 5: the shutdown-fault case, against a SLOW registry. A separate,
// minimal (single source loop) pipeline — GetMirrorState needs no wireauth
// (see the file doc), and the drain never reaches MirrorLogSegment at all
// (the first call in tlogship.Shipper.tick already hangs past the budget),
// so no DID resolution is needed here whatsoever.
// ─────────────────────────────────────────────────────────────────────────

const (
	sepShutSrcIssuerDID = "did:dplaax:reg:org:acme:pipeline:shutsrc:process:s1"
	sepShutSrcPipeline  = "did:dplaax:reg:org:acme:pipeline:shutsrc"
	sepShutSrcIngress   = "ingest.sep.shutsrc"
)

// TestSeparatedTopology_ShutdownFaultHonorsDrainBudget proves the D8 ordered
// shutdown's final flush (run's step 4, drainShippers) against a REAL
// registry that never answers a TlogService request: run still returns nil
// (a timed-out final drain is not a shutdown failure — see DefaultDrainBudget's
// own doc) within roughly DefaultDrainBudget of the simulated SIGTERM, and
// logs the documented unmirrored-tail line.
func TestSeparatedTopology_ShutdownFaultHonorsDrainBudget(t *testing.T) {
	ks := ksfilestore.New(t.TempDir())
	gen := ed25519.Generator{}
	// The node identity happens to equal the source loop's own output
	// subject here — harmless either way post-D9 (buildDeps' payload-retain
	// client now signs each retain as the OWNING loop's own output subject
	// via payloadClientFactory, not the shared node identity), kept only
	// because this identity's key is what gets provisioned below.
	// RetainPayload runs at boot (VCResolverService/PayloadStoreService stay
	// fast — only TlogService is slowed below), so this identity DOES need
	// to resolve, unlike a case with no producing loop at all.
	//
	// Saved BEFORE the process identity below: ksfilestore.SaveKeyPair is
	// create-only or keyed on a DIRECTORY it will not overwrite, and
	// sepShutSrcPipeline's own directory is a path ANCESTOR of
	// sepShutSrcIssuerDID's (pipeline:shutsrc vs pipeline:shutsrc:process:s1)
	// — saving the deeper path first would implicitly create the ancestor
	// directory as a side effect of MkdirAll, making this save fail with a
	// false "keyset already exists".
	nodeKP, err := gen.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.SaveKeyPair(sepShutSrcPipeline, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: nodeKP}); err != nil {
		t.Fatal(err)
	}
	kp, err := gen.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.SaveKeyPair(sepShutSrcIssuerDID, map[keystore.KeyID]*crypto.KeyPair{
		keystore.KeyIDSigning: kp, keystore.KeyIDAuth: kp,
	}); err != nil {
		t.Fatal(err)
	}

	fakeDIDURL := newSepFakeDIDServer(t, map[string]*did.DIDDocument{
		sepShutSrcPipeline: sepIdentityDoc(t, sepShutSrcPipeline, nodeKP.PublicKey),
	})

	// Every TlogService request (GetMirrorState included) hangs until the
	// caller's own context gives up. VCResolverService stays fast, so the
	// source loop's own publish-on-emit succeeds normally at boot.
	// A bounded sleep, not <-r.Context().Done(): an HTTP/1.1 server's request
	// context is only cancelled by the underlying connection closing or the
	// handler itself returning, neither of which the CLIENT's own context
	// deadline (drainShippers' 10s budget) reliably triggers — the client
	// gives up and returns an error to its caller, but the connection can sit
	// idle with this handler goroutine still blocked, which would otherwise
	// hang httptest.Server.Close() in this test's own cleanup forever. A fixed
	// sleep comfortably longer than DefaultDrainBudget still proves the
	// client-side timeout (the client always gives up first), while
	// guaranteeing this handler — and so Close() — eventually returns.
	const slowTlogSleep = DefaultDrainBudget + 5*time.Second
	slowTlog := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/dplaax.tlog.v1.TlogService/") {
				time.Sleep(slowTlogSleep)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	reg := buildSepRegistry(t, fakeDIDURL, nil, slowTlog)

	pipeCfg := &pipelineconfig.Config{
		VCStoreEndpoint:   reg.url,
		VCStoreBearer:     sepBearer,
		MaxCredentialSize: 1 << 20,
		TlogMirror:        pipelineconfig.TlogMirrorConfig{MaxBatchRecords: 256, MaxBatchBytes: 4 << 20, FlushInterval: time.Hour},
		Loops: []pipelineconfig.LoopConfig{{
			Name: "shutsrc", Role: pipelineconfig.RoleSource, IngressSubject: sepShutSrcIngress,
			Source: pipelineconfig.SourceConfig{
				OutputSubject: sepShutSrcPipeline,
				Issuer:        pipelineconfig.IssuerConfig{DID: sepShutSrcIssuerDID, KeyID: string(keystore.KeyIDSigning), VerificationMethod: sepShutSrcIssuerDID + "#signing"},
				PipelineID:    "shutsrc", ProcessID: "s1", TransformationClaim: vc.ClaimConvert,
			},
		}},
	}

	natsURL := runEmbeddedNATS(t)
	acc, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	accSeed, err := acc.Seed()
	if err != nil {
		t.Fatal(err)
	}
	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: natsURL, AccountSeed: string(accSeed), NodeDID: sepShutSrcPipeline},
	}
	rtCfg, err := pipelineRuntimeConfigFrom(chainCfg, pipeCfg, t.TempDir())
	if err != nil {
		t.Fatalf("pipelineRuntimeConfigFrom: %v", err)
	}

	guard := core.NewURLGuard(core.WithAllowLoopback(true))
	// No consuming loop in this pipeline, so no resolver is needed at all.
	deps := buildDeps(pipeCfg, ks, guard, nil, sepShutSrcPipeline)
	dp, err := pipelineruntime.Build(context.Background(), &rtCfg, ks, deps)
	if err != nil {
		t.Fatalf("pipelineruntime.Build: %v", err)
	}

	mirrorFactory := newMirrorClientFactory(ks, reg.url, sepBearer, guard.HTTPClient())
	shippers, err := buildShippers(dp.CustodyLogs(), mirrorFactory.forClient, pipeCfg.TlogMirror)
	if err != nil {
		t.Fatalf("buildShippers: %v", err)
	}
	if len(shippers) != 1 {
		t.Fatalf("custody logs = %d, want 1 (the source's emission log)", len(shippers))
	}

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	srv, listen, _ := newLoopbackServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))

	runCtx, runCancel := context.WithCancel(context.Background())
	runResult := make(chan error, 1)
	go func() { runResult <- run(runCtx, srv, listen, dp, shippers, nil, DefaultDrainBudget) }()

	inj, err := natstransport.Connect(context.Background(), natstransport.Config{URL: natsURL, AccountSeed: string(accSeed)})
	if err != nil {
		t.Fatalf("injector connect: %v", err)
	}
	t.Cleanup(func() { _ = inj.Close() })
	out := make(chan []byte, 4)
	if err := inj.Subscriber(sepShutSrcPipeline).Subscribe(func(b []byte) {
		select {
		case out <- b:
		default:
		}
	}); err != nil {
		t.Fatalf("observe: %v", err)
	}
	pub := inj.Publisher(sepShutSrcIngress)
	sepRetryUntil(t, 15*time.Second, 150*time.Millisecond, func() { _ = pub.Publish([]byte(`{"reading":1}`)) }, func() bool {
		select {
		case <-out:
			return true
		default:
			return false
		}
	})
	// Let the emission's tlog append settle before signalling shutdown.
	time.Sleep(300 * time.Millisecond)

	start := time.Now()
	runCancel() // simulate SIGTERM

	select {
	case runErr := <-runResult:
		elapsed := time.Since(start)
		if runErr != nil {
			t.Fatalf("run returned %v, want nil (a timed-out final drain must still exit clean)", runErr)
		}
		if elapsed < DefaultDrainBudget-2*time.Second {
			t.Errorf("run returned after %s — want it bounded by roughly DefaultDrainBudget (%s), not finish suspiciously early", elapsed, DefaultDrainBudget)
		}
		if elapsed > DefaultDrainBudget+10*time.Second {
			t.Errorf("run took %s — want bounded near DefaultDrainBudget (%s)", elapsed, DefaultDrainBudget)
		}
	case <-time.After(DefaultDrainBudget + time.Minute):
		t.Fatal("run did not return within the expected bound")
	}

	const wantMsg = "local durable tail remains unmirrored (resume re-ships it)"
	if got := logBuf.String(); !strings.Contains(got, wantMsg) {
		t.Errorf("log output does not contain %q:\n%s", wantMsg, got)
	}
}
