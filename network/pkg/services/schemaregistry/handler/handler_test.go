package handler_test

import (
	"bytes"
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"

	schemav1 "github.com/provin-line/oss/gen/go/dplaax/schema/v1"
	schemav1connect "github.com/provin-line/oss/gen/go/dplaax/schema/v1/v1connect"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry/handler"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry/store/yamlstore"
)

var validBody = []byte(`{"type":"object","required":["reading"],"properties":{"reading":{"type":"number"}}}`)

// testClient stands up the full proto→handler→service→yamlstore path behind an
// in-process Connect server (Connect protocol over HTTP/1.1 — no extra
// dependency; production serves the same handler over h2c). Returns a client.
func testClient(t *testing.T) schemav1connect.SchemaServiceClient {
	t.Helper()
	clock := func() time.Time { return time.Date(2026, 6, 14, 9, 0, 0, 0, time.UTC) }
	svc := schemaregistry.New(yamlstore.New(t.TempDir()), schemaregistry.WithClock(clock))
	_, h := schemav1connect.NewSchemaServiceHandler(handler.New(svc))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return schemav1connect.NewSchemaServiceClient(srv.Client(), srv.URL)
}

func mustRegister(t *testing.T, c schemav1connect.SchemaServiceClient, name, prerelease string, body []byte) *schemav1.Schema {
	t.Helper()
	resp, err := c.RegisterSchema(context.Background(), connect.NewRequest(&schemav1.RegisterSchemaRequest{
		Name: name, SchemaFormat: "JsonSchema", SchemaBody: body, Prerelease: prerelease,
	}))
	if err != nil {
		t.Fatalf("RegisterSchema(%s): %v", name, err)
	}
	return resp.Msg.GetSchema()
}

func TestRegisterGet_RoundTrip(t *testing.T) {
	c := testClient(t)
	reg := mustRegister(t, c, "reading", "", validBody)
	if reg.GetVersion() == "" {
		t.Fatal("no version assigned")
	}
	got, err := c.GetSchema(context.Background(), connect.NewRequest(&schemav1.GetSchemaRequest{
		Name: "reading", Version: reg.GetVersion(),
	}))
	if err != nil {
		t.Fatalf("GetSchema: %v", err)
	}
	if !bytes.Equal(got.Msg.GetSchema().GetSchemaBody(), validBody) {
		t.Errorf("body not byte-faithful over the wire: %q", got.Msg.GetSchema().GetSchemaBody())
	}
}

func TestRegister_Idempotent(t *testing.T) {
	c := testClient(t)
	a := mustRegister(t, c, "reading", "", validBody)
	b := mustRegister(t, c, "reading", "", validBody)
	if a.GetVersion() != b.GetVersion() {
		t.Errorf("idempotency broken over the wire: %q != %q", a.GetVersion(), b.GetVersion())
	}
}

func TestGet_UnknownIsNotFound(t *testing.T) {
	c := testClient(t)
	_, err := c.GetSchema(context.Background(), connect.NewRequest(&schemav1.GetSchemaRequest{
		Name: "reading", Version: "2026-06-14-deadbeefdeadbeef",
	}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("got code %v, want NotFound", connect.CodeOf(err))
	}
}

func TestList_Filters(t *testing.T) {
	c := testClient(t)
	mustRegister(t, c, "reading", "", validBody)           // stable
	pre := mustRegister(t, c, "reading", "rc1", validBody) // prerelease (distinct version)
	if _, err := c.DeprecateSchema(context.Background(), connect.NewRequest(&schemav1.DeprecateSchemaRequest{
		Name: "reading", Version: pre.GetVersion(),
	})); err != nil {
		t.Fatalf("DeprecateSchema: %v", err)
	}

	def, err := c.ListSchemas(context.Background(), connect.NewRequest(&schemav1.ListSchemasRequest{Name: "reading"}))
	if err != nil {
		t.Fatalf("ListSchemas: %v", err)
	}
	if n := len(def.Msg.GetSchemas()); n != 1 {
		t.Errorf("default list: got %d, want 1 (stable only)", n)
	}

	all, err := c.ListSchemas(context.Background(), connect.NewRequest(&schemav1.ListSchemasRequest{
		Name: "reading", IncludeDeprecated: true, IncludePrerelease: true,
	}))
	if err != nil {
		t.Fatalf("ListSchemas all: %v", err)
	}
	if n := len(all.Msg.GetSchemas()); n != 2 {
		t.Errorf("inclusive list: got %d, want 2", n)
	}
}

func TestRegister_PathTraversalName_InvalidArgument(t *testing.T) {
	c := testClient(t)
	_, err := c.RegisterSchema(context.Background(), connect.NewRequest(&schemav1.RegisterSchemaRequest{
		Name: "../evil", SchemaFormat: "JsonSchema", SchemaBody: validBody,
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("got code %v, want InvalidArgument", connect.CodeOf(err))
	}
}

// D2: every rejection mode of the admission check surfaces as InvalidArgument
// over the wire, and none of the rejected bodies is registered.
func TestRegister_InvalidSchemaBodies_InvalidArgument(t *testing.T) {
	c := testClient(t)
	bodies := map[string][]byte{
		"structurally invalid": []byte(`{"type":123}`),
		"external $ref":        []byte(`{"$ref":"file:///etc/passwd"}`),
		"duplicate key":        []byte(`{"type":"object","type":"array"}`),
		"unsupported format":   validBody, // sent with a non-JsonSchema format below
	}
	for label, body := range bodies {
		format := "JsonSchema"
		if label == "unsupported format" {
			format = "Cddl"
		}
		_, err := c.RegisterSchema(context.Background(), connect.NewRequest(&schemav1.RegisterSchemaRequest{
			Name: "reading", SchemaFormat: format, SchemaBody: body,
		}))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: got code %v, want InvalidArgument", label, connect.CodeOf(err))
		}
	}
	list, err := c.ListSchemas(context.Background(), connect.NewRequest(&schemav1.ListSchemasRequest{
		Name: "reading", IncludeDeprecated: true, IncludePrerelease: true,
	}))
	if err != nil {
		t.Fatalf("ListSchemas: %v", err)
	}
	if n := len(list.Msg.GetSchemas()); n != 0 {
		t.Errorf("rejected schemas leaked into the registry over the wire: %d", n)
	}
}
