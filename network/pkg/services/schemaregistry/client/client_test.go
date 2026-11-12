package client_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	schemapb "github.com/provin-line/oss/gen/go/dplaax/schema/v1"
	"github.com/provin-line/oss/gen/go/dplaax/schema/v1/schemapbconnect"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry/client"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry/handler"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry/store/yamlstore"
)

var validBody = []byte(`{"type":"object","required":["reading"],"properties":{"reading":{"type":"number"}}}`)

// registryServer stands up the REAL proto→handler→service→yamlstore path
// behind an httptest server — the schemaregistry handler test's own harness
// idiom (handler/handler_test.go's testClient), reused here so the client
// under test is exercised against the same real handler a production node
// mounts, never a fake. Returns the server's base URL, its *http.Client, and
// a raw generated client for seeding fixtures: the client under test only
// ever calls GetSchema, so RegisterSchema/DeprecateSchema go through this
// separate seed handle.
func registryServer(t *testing.T) (url string, httpc *http.Client, seed schemapbconnect.SchemaServiceClient) {
	t.Helper()
	clock := func() time.Time { return time.Date(2026, 6, 20, 9, 0, 0, 0, time.UTC) }
	svc := schemaregistry.New(yamlstore.New(t.TempDir()), schemaregistry.WithClock(clock))
	_, h := schemapbconnect.NewSchemaServiceHandler(handler.New(svc))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL, srv.Client(), schemapbconnect.NewSchemaServiceClient(srv.Client(), srv.URL)
}

func mustRegister(t *testing.T, seed schemapbconnect.SchemaServiceClient, name, prerelease string, body []byte) *schemapb.Schema {
	t.Helper()
	resp, err := seed.RegisterSchema(context.Background(), connect.NewRequest(&schemapb.RegisterSchemaRequest{
		Name: name, SchemaFormat: "JsonSchema", SchemaBody: body, Prerelease: prerelease,
	}))
	if err != nil {
		t.Fatalf("RegisterSchema(%s): %v", name, err)
	}
	return resp.Msg.GetSchema()
}

// GetSchema round-trips a registered schema's body/format/version, byte- and
// field-faithfully, over the real wire.
func TestGetSchema_RoundTrip(t *testing.T) {
	url, httpc, seed := registryServer(t)
	reg := mustRegister(t, seed, "reading", "", validBody)

	c := client.New(client.Config{BaseURL: url, HTTPClient: httpc})
	got, err := c.GetSchema(context.Background(), "reading", reg.GetVersion())
	if err != nil {
		t.Fatalf("GetSchema: %v", err)
	}
	if got.Version != reg.GetVersion() {
		t.Errorf("Version = %q, want %q", got.Version, reg.GetVersion())
	}
	if got.Format != "JsonSchema" {
		t.Errorf("Format = %q, want %q", got.Format, "JsonSchema")
	}
	if !bytes.Equal(got.Body, validBody) {
		t.Errorf("Body not byte-faithful over the wire: %q", got.Body)
	}
	if got.Deprecated {
		t.Error("Deprecated = true, want false for a freshly registered schema")
	}
}

// A remote NotFound maps to client.ErrNotFound (errors.Is) — GetSchema has no
// "latest" resolution, so an unknown (name, version) is always a definitive
// miss, never an ambiguity.
func TestGetSchema_UnknownIsErrNotFound(t *testing.T) {
	url, httpc, _ := registryServer(t)
	c := client.New(client.Config{BaseURL: url, HTTPClient: httpc})

	_, err := c.GetSchema(context.Background(), "reading", "2026-06-14-deadbeefdeadbeef")
	if !errors.Is(err, client.ErrNotFound) {
		t.Errorf("err = %v, want client.ErrNotFound", err)
	}
}

// The Deprecated soft flag survives the wire round-trip; the body stays
// retained (deprecation never deletes — schemaregistry's own package doc).
func TestGetSchema_DeprecatedFlagCarried(t *testing.T) {
	url, httpc, seed := registryServer(t)
	reg := mustRegister(t, seed, "reading", "", validBody)
	if _, err := seed.DeprecateSchema(context.Background(), connect.NewRequest(&schemapb.DeprecateSchemaRequest{
		Name: "reading", Version: reg.GetVersion(),
	})); err != nil {
		t.Fatalf("DeprecateSchema: %v", err)
	}

	c := client.New(client.Config{BaseURL: url, HTTPClient: httpc})
	got, err := c.GetSchema(context.Background(), "reading", reg.GetVersion())
	if err != nil {
		t.Fatalf("GetSchema: %v", err)
	}
	if !got.Deprecated {
		t.Error("Deprecated = false, want true after DeprecateSchema")
	}
	if !bytes.Equal(got.Body, validBody) {
		t.Errorf("Body not retained after deprecation: %q", got.Body)
	}
}

// spy wraps h, recording the Authorization header of every request it sees
// before delegating unmodified to h — proves the client's bearerInterceptor
// actually attaches the header on the wire, without pulling the L1 authz
// stack (network/pkg/auth) into this leaf client's own tests (the sibling
// handler/enforcement_test.go already covers what the L1 gate does with that
// header once presented).
type spy struct {
	http.Handler
	got string
}

func (s *spy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.got = r.Header.Get("Authorization")
	s.Handler.ServeHTTP(w, r)
}

func TestGetSchema_BearerAttached(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 6, 20, 9, 0, 0, 0, time.UTC) }
	svc := schemaregistry.New(yamlstore.New(t.TempDir()), schemaregistry.WithClock(clock))
	_, h := schemapbconnect.NewSchemaServiceHandler(handler.New(svc))
	sp := &spy{Handler: h}
	srv := httptest.NewServer(sp)
	t.Cleanup(srv.Close)

	c := client.New(client.Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Bearer: "test-l1-token"})
	// NotFound is fine here — only the header the request arrived with matters.
	_, _ = c.GetSchema(context.Background(), "reading", "absent")

	if want := "Bearer test-l1-token"; sp.got != want {
		t.Errorf("Authorization header = %q, want %q", sp.got, want)
	}
}

// With a bearer, the client follows no redirect, whatever *http.Client it is
// given: the bearer goes to BaseURL's origin only.
func TestBearer_ShownToNoServerTheEndpointRedirectsTo(t *testing.T) {
	url, counts := redirectingServer(t)
	c := client.New(client.Config{BaseURL: url, HTTPClient: &http.Client{}, Bearer: "node-token"})
	if _, err := c.GetSchema(context.Background(), "example", "1.0.0"); err == nil {
		t.Error("a redirected call succeeded")
	}
	if counts.hits.Load() == 0 || !counts.bearerShown.Load() {
		t.Fatalf("the endpoint answered %d requests, bearer shown %v; want the call to reach it with the bearer", counts.hits.Load(), counts.bearerShown.Load())
	}
	if n := counts.followed.Load(); n != 0 {
		t.Errorf("the client followed the redirect: the server it points to answered %d requests", n)
	}
}

// redirectCounts is what redirectingServer saw: the requests its endpoint
// answered, whether one carried a bearer, and the requests that reached the
// server it redirects to.
type redirectCounts struct {
	hits        atomic.Int32
	bearerShown atomic.Bool
	followed    atomic.Int32
}

// redirectingServer answers every request with a redirect to a second server
// on the same host, over HTTP/1.1, where net/http carries an Authorization
// header on to the same host.
func redirectingServer(t *testing.T) (string, *redirectCounts) {
	t.Helper()
	counts := &redirectCounts{}
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counts.followed.Add(1)
		http.Error(w, "no", http.StatusNotFound)
	}))
	t.Cleanup(other.Close)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counts.hits.Add(1)
		if r.Header.Get("Authorization") == "Bearer node-token" {
			counts.bearerShown.Store(true)
		}
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(redirector.Close)
	return redirector.URL, counts
}
