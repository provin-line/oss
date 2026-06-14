package handler_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/o3co/protobuf.interceptors/endpoint"
	policy "github.com/o3co/protobuf.interceptors/schema"
	"google.golang.org/protobuf/proto"

	schemav1 "github.com/provin-line/oss/gen/go/dplaax/schema/v1"
	schemav1connect "github.com/provin-line/oss/gen/go/dplaax/schema/v1/v1connect"
	"github.com/provin-line/oss/network/pkg/auth"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry/handler"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry/store/yamlstore"
)

// authClient stands up the SchemaService behind the authorization interceptor
// chain (auth.Interceptors) backed by a static verifier with the given rules.
func authClient(t *testing.T, rules []endpoint.StaticRule) schemav1connect.SchemaServiceClient {
	t.Helper()
	clock := func() time.Time { return time.Date(2026, 6, 15, 9, 0, 0, 0, time.UTC) }
	svc := schemaregistry.New(yamlstore.New(t.TempDir()), schemaregistry.WithClock(clock))
	_, h := schemav1connect.NewSchemaServiceHandler(
		handler.New(svc),
		connect.WithInterceptors(auth.Interceptors(endpoint.NewStaticEndpoint(rules))...),
	)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return schemav1connect.NewSchemaServiceClient(srv.Client(), srv.URL)
}

func registerReq(token string) *connect.Request[schemav1.RegisterSchemaRequest] {
	req := connect.NewRequest(&schemav1.RegisterSchemaRequest{
		Name: "reading", SchemaFormat: "JsonSchema", SchemaBody: validBody,
	})
	if token != "" {
		req.Header().Set("Authorization", "Bearer "+token)
	}
	return req
}

func TestEnforcement_Allowed(t *testing.T) {
	c := authClient(t, []endpoint.StaticRule{{Resource: "schemas", Action: "register"}})
	if _, err := c.RegisterSchema(context.Background(), registerReq("dummy")); err != nil {
		t.Errorf("allowed register: want success, got %v (code %v)", err, connect.CodeOf(err))
	}
}

func TestEnforcement_Denied(t *testing.T) {
	// Only "read" is allowed; "register" must be denied.
	c := authClient(t, []endpoint.StaticRule{{Resource: "schemas", Action: "read"}})
	_, err := c.RegisterSchema(context.Background(), registerReq("dummy"))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("denied register: want CodePermissionDenied, got %v (%v)", connect.CodeOf(err), err)
	}
}

func TestEnforcement_MissingToken(t *testing.T) {
	// Policy-protected RPC with no bearer token → Unauthenticated (the verifier
	// requires the token before any allow/deny).
	c := authClient(t, []endpoint.StaticRule{{Resource: "schemas", Action: "register"}})
	_, err := c.RegisterSchema(context.Background(), registerReq(""))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("missing token: want CodeUnauthenticated, got %v (%v)", connect.CodeOf(err), err)
	}
}

// Fail-open guard: every SchemaService RPC must carry the o3co.authz.v1.policy
// option. A missing option silently disables the authorization check, so this
// catches an accidentally-unprotected RPC at build time.
func TestSchemaService_AllRPCsAnnotated(t *testing.T) {
	methods := schemav1.File_dplaax_schema_v1_schema_proto.Services().ByName("SchemaService").Methods()
	if methods.Len() != 4 {
		t.Fatalf("SchemaService has %d methods, want 4", methods.Len())
	}
	for i := 0; i < methods.Len(); i++ {
		m := methods.Get(i)
		if !proto.HasExtension(m.Options(), policy.E_Policy) {
			t.Errorf("RPC %s is missing the o3co.authz.v1.policy option (would be unprotected)", m.Name())
		}
	}
}
