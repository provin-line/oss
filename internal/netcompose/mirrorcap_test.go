package netcompose

// Task 5 review (M-1): MirrorLogSegment's mount cap must be derived from
// tlog-mirror.max-batch-bytes, not borrowed from max-credential-size (an
// unrelated class — the single-VC StoreVC/fetch path). This file proves it
// through the REAL BuildHandler + REAL connect transport, not a direct Go
// method call (mirror_test.go's handler-level tests bypass connect's own
// read-cap enforcement entirely, since they call h.MirrorLogSegment(ctx,
// req) directly).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/o3co/protobuf.interceptors/endpoint"

	tlogpb "github.com/provin-line/oss/gen/go/dplaax/tlog/v1"
	"github.com/provin-line/oss/gen/go/dplaax/tlog/v1/tlogpbconnect"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/registry"
	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver"
	payloadmemstore "github.com/provin-line/oss/network/pkg/services/payloadresolver/memstore"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry"
	schemayaml "github.com/provin-line/oss/network/pkg/services/schemaregistry/store/yamlstore"
	"github.com/provin-line/oss/network/pkg/services/tlogservice/mirrorstore"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
)

// assembledHandlerWithMirror is assembledHandlerWith's mirror-wired sibling:
// it additionally opens a real mirrorstore.Store and wires it via
// MirrorWiring, so a test can drive MirrorLogSegment's mount cap through the
// real assembled mux instead of calling the handler method in-process.
func assembledHandlerWithMirror(t *testing.T, maxCredentialSize, maxBatchRecords, maxBatchBytes int) http.Handler {
	t.Helper()
	coreCfg := &core.CoreConfig{DataDir: t.TempDir(), ListenAddr: ":0", AllowLoopback: true}
	regCfg := &registry.RegistryConfig{ID: registryID}
	verifier := endpoint.NewStaticEndpoint([]endpoint.StaticRule{
		{Resource: "tlog", Action: "mirror"},
	})
	chainCfg := natsChainCfg(t)
	guard, resolver, derr := NewDIDResolution(coreCfg, chainCfg)
	if derr != nil {
		t.Fatalf("NewDIDResolution: %v", derr)
	}
	vcSvc := vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), memstore.NewPool())
	chainOp, err := ChainOperator(chainCfg)
	if err != nil {
		t.Fatalf("ChainOperator: %v", err)
	}
	schemaSvc := schemaregistry.New(schemayaml.New(t.TempDir()))
	payloadStore := payloadmemstore.New()
	store, err := mirrorstore.Open(t.TempDir())
	if err != nil {
		t.Fatalf("mirrorstore.Open: %v", err)
	}
	mirror := &MirrorWiring{Store: store, MaxBatchRecords: maxBatchRecords, MaxBatchBytes: maxBatchBytes}
	h, err := BuildHandler(coreCfg, regCfg, chainCfg, chainOp, verifier, guard, resolver, vcSvc,
		auditor.NewMemStatusStore(), auditor.NewMemReceiptStore(), auditor.NewMemQueue(),
		schemaSvc, payloadresolver.New(payloadStore), payloadStore, nil, mirror,
		maxCredentialSize, 1<<20, 64<<20, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildHandler: %v", err)
	}
	return h
}

// TestMirrorLogSegment_MountCapDerivedFromMaxBatchBytes drives a 2 MiB batch
// — legitimately under tlog-mirror.max-batch-bytes (the repo's shipped
// default, 4 MiB) but well over max-credential-size (the repo's shipped
// default, 1 MiB) — through the real assembled mux. The request carries NO
// AuthProof, so IF it reaches the RPC handler at all, the deterministic
// outcome is CodeInvalidArgument (decodeProof's missing-proof case) — a code
// connect's own read-cap enforcement can NEVER return (that path always
// returns CodeResourceExhausted, "message size N is larger than configured
// max M", before the message is ever decoded far enough to see a missing
// field). CodeResourceExhausted here can therefore only mean one thing: the
// mount cap rejected a legitimately batch-cap-sized request before it ever
// reached the handler — exactly the old (plain max-credential-size) mount's
// bug. Confirmed by reverting the mount to connect.WithReadMaxBytes(maxCredentialSize):
// this test then fails with CodeResourceExhausted.
func TestMirrorLogSegment_MountCapDerivedFromMaxBatchBytes(t *testing.T) {
	const maxCredentialSize = 1 << 20 // the repo's shipped default
	const maxBatchBytes = 4 << 20     // the repo's shipped default
	h := assembledHandlerWithMirror(t, maxCredentialSize, 256, maxBatchBytes)
	srv := httptest.NewServer(h)
	defer srv.Close()

	// The L1 authz interceptor runs before the RPC method — any bearer is
	// admitted by the static endpoint's grant list, which is keyed on
	// resource/action, not the token's own value.
	client := tlogpbconnect.NewTlogServiceClient(http.DefaultClient, srv.URL, connect.WithInterceptors(BearerInterceptor("test-bearer")))
	big := make([]byte, 2<<20) // between max-credential-size and max-batch-bytes
	req := connect.NewRequest(&tlogpb.MirrorLogSegmentRequest{
		LogId: pipelineDID, FromIndex: 0, RecordPayloads: [][]byte{big},
		Checkpoint: &tlogpb.GetLogCheckpointResponse{Size: "1"},
	})
	_, err := client.MirrorLogSegment(context.Background(), req)
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("2 MiB batch (between max-credential-size and max-batch-bytes): code = %v, want InvalidArgument (a missing proof — proves the request reached the handler, i.e. was NOT rejected at the connect read cap); err=%v", connect.CodeOf(err), err)
	}
}
