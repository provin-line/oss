package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/gen/go/dplaax/vc/v1/vcpbconnect"
	"github.com/provin-line/oss/internal/netcompose"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	payloadclient "github.com/provin-line/oss/network/pkg/services/payloadresolver/client"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry/store"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	vcresolverclient "github.com/provin-line/oss/network/pkg/services/vcresolver/client"
	"github.com/provin-line/oss/pipeline/contract"
	pipelineruntime "github.com/provin-line/oss/pipeline/runtime"
	"github.com/provin-line/oss/vc"
	"github.com/provin-line/oss/vc/chainwalk"
)

// The vcresolver client is the network credential resolver a full-chain verifier walks.
// The compile-time CredentialResolver assertion lives here (the consumer that imports
// both network/ and pipeline/), keeping the client package free of any pipeline/ import
// (AGENTS.md layer rule 2) — relocated from pipeline/runtime/dataplane.go by the
// boundary severance, which forbids pipeline/runtime importing network/ at all.
var _ chainwalk.CredentialResolver = (*vcresolverclient.Resolver)(nil)

// The payload client is the network by-reference payload resolver consuming loops
// fetch through. Its contract.PayloadResolver assertion lives here for the same
// reason — relocated from pipeline/runtime/dataplane.go by the boundary severance.
var _ contract.PayloadResolver = (*payloadclient.Resolver)(nil)

// runtimeConfigFrom maps the network config trees (chainconfig.Config +
// pipelineconfig.Config) into pipeline/runtime's own, network-agnostic
// Config — the drift guard between the two config trees is
// runtimewiring_test.go's golden mapping test. dataDir is the node's data
// directory (coreCfg.DataDir); TlogDir/RejectLogDir derive from it exactly as
// main's pre-severance literals did (data-dir/tlog,
// data-dir/evidence/sink-rejects). An EMPTY dataDir leaves both unset —
// pipeline/runtime.Build's unit-test seam (in-memory logs instead of durable
// ones) — so callers that do not care about log durability (this package's
// own tests) can opt out without conjuring a temp directory.
//
// A non-NATS transport (the dev-only noop transport) WITH configured loops
// is a boot error, naming the offending transport — the FAITHFUL relocation
// of pipeline/runtime's pre-severance in-Build "data-plane loops require the
// nats transport" guard (fail-closed: a data-plane loop has nothing to run
// on without nats, so this must not silently degrade to zero loops). Zero
// loops on a non-NATS transport is fine (nothing to guard); Build's own
// empty-NATS-URL guard is independent defense-in-depth, not a substitute —
// it fires only inside Build, given a Config already carrying loops, and
// cannot see or name the transport that produced it.
func runtimeConfigFrom(chainCfg *chainconfig.Config, pipeCfg *pipelineconfig.Config, dataDir string) (pipelineruntime.Config, error) {
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
			// No "standalone:" prefix here — main.go's log.Fatalf("standalone: %v")
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
// deliberately NOT copied: pipeline/runtime's buildAggregateProcess never
// reads it (the aggregate runtime declares VerificationAdjacent
// intrinsically), so runtime.AggregateConfig has no field for it.
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

// ingressStoreAdapter adapts *vcresolver.Service (the node's local VC store)
// to pipeline/runtime's network-agnostic IngressStorer seam: runtime
// consumes only the stored head's body address (ingressstore.go's sole
// read), so the adapter unwraps vcresolver.StoreVCResult to that one field.
type ingressStoreAdapter struct {
	svc *vcresolver.Service
}

func (a ingressStoreAdapter) StoreVC(ctx context.Context, credential []byte, upstreamEndpoint string, assemblyDepth int) (string, error) {
	res, err := a.svc.StoreVC(ctx, credential, upstreamEndpoint, assemblyDepth)
	if err != nil {
		return "", err
	}
	return res.BodyAddress, nil
}

// schemaGetterAdapter adapts *schemaregistry.Service to pipeline/runtime's
// network-agnostic SchemaGetter seam, translating the registry's own
// store.ErrNotFound into runtime's ErrSchemaNotFound sentinel.
type schemaGetterAdapter struct {
	svc *schemaregistry.Service
}

func (a schemaGetterAdapter) Get(ctx context.Context, name, version string) (*pipelineruntime.Schema, error) {
	sc, err := a.svc.Get(ctx, name, version)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, pipelineruntime.ErrSchemaNotFound
		}
		return nil, err
	}
	return &pipelineruntime.Schema{Format: sc.SchemaFormat, Body: sc.SchemaBody, Deprecated: sc.Deprecated}, nil
}

// credentialPublisherAdapter adapts *vcresolverclient.Resolver to
// pipeline/runtime's network-agnostic CredentialPublisher seam.
type credentialPublisherAdapter struct {
	inner *vcresolverclient.Resolver
}

func (a credentialPublisherAdapter) StoreCredential(ctx context.Context, cred *vc.PipelinePassCredential, upstreamEndpoint string) (pipelineruntime.StoredCredential, error) {
	sc, err := a.inner.StoreCredential(ctx, cred, upstreamEndpoint)
	if err != nil {
		return pipelineruntime.StoredCredential{}, err
	}
	return pipelineruntime.StoredCredential{BodyAddress: sc.BodyAddress, WireVariantID: sc.WireVariantID}, nil
}

// credentialPublisherFrom constructs the composition-root's VC-store client
// exactly as pipeline/runtime's Build did before the boundary severance
// (same options, including WithReadMaxBytes(pipeCfg.MaxCredentialSize) —
// D-17g-13). Moved here because the construction needs
// network/pkg/services/vcresolver/client, and pipeline/runtime must not
// import network/ at all. Returns nil when no vc-store-endpoint is
// configured — no publication, the same semantics Build enforced itself
// pre-severance. httpClient nil defaults to http.DefaultClient (unchanged:
// main does not override it; only tests inject one, e.g. an embedded
// server's client).
func credentialPublisherFrom(pipeCfg *pipelineconfig.Config, httpClient connect.HTTPClient) pipelineruntime.CredentialPublisher {
	if pipeCfg.VCStoreEndpoint == "" {
		return nil
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	client := vcresolverclient.New(vcpbconnect.NewVCResolverServiceClient(
		httpClient, pipeCfg.VCStoreEndpoint,
		connect.WithInterceptors(netcompose.BearerInterceptor(pipeCfg.VCStoreBearer)),
		connect.WithReadMaxBytes(pipeCfg.MaxCredentialSize), // D-17g-13: bound a resolved VC (protects 17e's full walk)
	))
	return credentialPublisherAdapter{inner: client}
}

// netcomposeMetricsFrom field-copies pipeline/runtime's own LoopMetrics into
// internal/netcompose's LoopMetrics — the metrics bridge's own type, which
// pipeline/runtime no longer imports (the boundary severance: network/ and
// pipeline/ never import each other). The per-loop accessor interfaces
// (EmitCounters/StrippedCounter/VerifyCounts) are declared with identical
// method sets in both packages, so each field is directly assignable
// interface-to-interface — no unwrapping needed.
func netcomposeMetricsFrom(lms []pipelineruntime.LoopMetrics) []netcompose.LoopMetrics {
	if lms == nil {
		return nil
	}
	out := make([]netcompose.LoopMetrics, len(lms))
	for i, lm := range lms {
		out[i] = netcompose.LoopMetrics{Name: lm.Name, Role: lm.Role, Emits: lm.Emits, Stripped: lm.Stripped, Verify: lm.Verify}
	}
	return out
}
