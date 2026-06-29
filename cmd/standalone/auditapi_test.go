package main

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/o3co/protobuf.interceptors/endpoint"

	auditpb "github.com/provin-line/oss/gen/go/dplaax/audit/v1"
	"github.com/provin-line/oss/gen/go/dplaax/audit/v1/auditpbconnect"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/registry"
	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	"github.com/provin-line/oss/vc"
)

// auditServer stands up the assembled mux with AuditService mounted behind a static
// authorizer granting {audit, read}, and returns the SHARED status store the audit
// runner would write — so a test can Put a verdict and read it back over the RPC,
// exercising the same instance both planes share (D-17i-7).
func auditServer(t *testing.T) (*httptest.Server, *auditor.MemStatusStore) {
	t.Helper()
	coreCfg := &core.CoreConfig{DataDir: t.TempDir(), ListenAddr: ":0", AllowLoopback: true}
	regCfg := &registry.RegistryConfig{ID: registryID}
	verifier := endpoint.NewStaticEndpoint([]endpoint.StaticRule{{Resource: "audit", Action: "read"}})
	chainCfg := natsChainCfg(t)
	guard, resolver := newDIDResolution(coreCfg, chainCfg)
	vcSvc := vcresolver.New(memstore.NewStore(), memstore.NewPool())
	status := auditor.NewMemStatusStore()
	h, err := BuildHandler(coreCfg, regCfg, chainCfg, verifier, guard, resolver, vcSvc, status, 1<<20)
	if err != nil {
		t.Fatalf("BuildHandler: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, status
}

// A verdict recorded by the runner is served over the mounted AuditService with its
// coverage intact: linear_chain present + VERIFIED, source_commitment ABSENT (the 17h-era
// linear-only coverage — a reader can never mistake it for a full aggregate verdict).
func TestAuditAPI_ServesRecordedVerdict(t *testing.T) {
	srv, status := auditServer(t)
	headHash := "sha256:" + strings.Repeat("a", 64)
	if err := status.Put(headHash, auditor.AuditRecord{
		Overall: vc.ConfidenceVerified,
		Axes: vc.AxisResult{
			DataIntegrity:      vc.ConfidenceVerified,
			SignerAuthenticity: vc.ConfidenceVerified,
			ChainConsistency:   vc.ConfidenceVerified,
		},
		Scope:     auditor.AuditScope{LinearChain: true},
		AuditedAt: time.Unix(1700000000, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	client := auditpbconnect.NewAuditServiceClient(srv.Client(), srv.URL)
	resp, err := client.GetAuditStatus(context.Background(),
		bearer(connect.NewRequest(&auditpb.GetAuditStatusRequest{HeadHash: headHash})))
	if err != nil {
		t.Fatalf("GetAuditStatus: %v (code %v)", err, connect.CodeOf(err))
	}
	if lc := resp.Msg.GetLinearChain(); lc == nil || lc.GetConfidence() != auditpb.Confidence_CONFIDENCE_VERIFIED {
		t.Errorf("linear_chain = %+v, want present + VERIFIED", lc)
	}
	if resp.Msg.GetSourceCommitment() != nil {
		t.Errorf("source_commitment = %+v, want nil (linear-only coverage)", resp.Msg.GetSourceCommitment())
	}
	if resp.Msg.GetAuditedAt() != "2023-11-14T22:13:20Z" {
		t.Errorf("audited_at = %q, want RFC3339 UTC", resp.Msg.GetAuditedAt())
	}
}

// The AuditService sits behind the L1 interceptor: no bearer → Unauthenticated (mirrors
// the VC-read gate).
func TestAuditAPI_RequiresAuth(t *testing.T) {
	srv, _ := auditServer(t)
	client := auditpbconnect.NewAuditServiceClient(srv.Client(), srv.URL)
	_, err := client.GetAuditStatus(context.Background(),
		connect.NewRequest(&auditpb.GetAuditStatusRequest{HeadHash: "sha256:" + strings.Repeat("a", 64)}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("no token: want Unauthenticated, got %v (%v)", connect.CodeOf(err), err)
	}
}
