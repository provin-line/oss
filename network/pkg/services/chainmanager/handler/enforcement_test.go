package handler_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/o3co/protobuf.interceptors/endpoint"

	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	"github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
	"github.com/provin-line/oss/network/pkg/auth"
	"github.com/provin-line/oss/network/pkg/services/chainmanager"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/handler"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store/memstore"
)

// authClient stands up the ChainService behind the authorization interceptor
// chain (auth.Interceptors) backed by a static verifier with the given rules —
// the schemaregistry/didregistry enforcement-test pattern, applied to the L1
// operator surface.
func authClient(t *testing.T, rules []endpoint.StaticRule) chainpbconnect.ChainServiceClient {
	t.Helper()
	svc := chainmanager.New(memstore.NewSubscriptionStore(), memstore.NewAllowListStore())
	_, h := chainpbconnect.NewChainServiceHandler(
		handler.NewOperator(svc),
		connect.WithInterceptors(auth.Interceptors(endpoint.NewStaticEndpoint(rules))...),
	)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return chainpbconnect.NewChainServiceClient(srv.Client(), srv.URL)
}

func updateReq(token string) *connect.Request[chainpb.UpdateAllowListRequest] {
	req := connect.NewRequest(&chainpb.UpdateAllowListRequest{
		PipelineDid: "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1",
		Rules:       []*chainpb.AllowRule{{Pattern: "did:dplaax:*:org:acme:*"}},
	})
	if token != "" {
		req.Header().Set("Authorization", "Bearer "+token)
	}
	return req
}

func TestEnforcement_Allowed(t *testing.T) {
	c := authClient(t, []endpoint.StaticRule{{Resource: "chain", Action: "update-allowlist"}})
	if _, err := c.UpdateAllowList(context.Background(), updateReq("dummy")); err != nil {
		t.Errorf("allowed update-allowlist: want success, got %v (code %v)", err, connect.CodeOf(err))
	}
}

func TestEnforcement_Denied(t *testing.T) {
	// Only "read" is granted; "update-allowlist" must be denied.
	c := authClient(t, []endpoint.StaticRule{{Resource: "chain", Action: "read"}})
	_, err := c.UpdateAllowList(context.Background(), updateReq("dummy"))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("denied update-allowlist: want CodePermissionDenied, got %v (%v)", connect.CodeOf(err), err)
	}
}

func TestEnforcement_MissingToken(t *testing.T) {
	// Policy-protected RPC with no bearer token → Unauthenticated.
	c := authClient(t, []endpoint.StaticRule{{Resource: "chain", Action: "update-allowlist"}})
	_, err := c.UpdateAllowList(context.Background(), updateReq(""))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("missing token: want CodeUnauthenticated, got %v (%v)", connect.CodeOf(err), err)
	}
}
