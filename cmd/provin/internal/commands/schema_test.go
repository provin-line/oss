package commands_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/cmd/provin/internal/commands"
	schemapb "github.com/provin-line/oss/gen/go/dplaax/schema/v1"
	"github.com/provin-line/oss/gen/go/dplaax/schema/v1/schemapbconnect"
)

// fakeSchemaService records every RegisterSchema request it receives and
// answers with a fixed, test-chosen version — enough to assert pass-through
// without replicating the real registry's version-derivation logic.
type fakeSchemaService struct {
	schemapbconnect.UnimplementedSchemaServiceHandler
	mu      sync.Mutex
	calls   []*schemapb.RegisterSchemaRequest
	version string
	err     error
}

func (f *fakeSchemaService) RegisterSchema(_ context.Context, req *connect.Request[schemapb.RegisterSchemaRequest]) (*connect.Response[schemapb.RegisterSchemaResponse], error) {
	f.mu.Lock()
	f.calls = append(f.calls, req.Msg)
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(&schemapb.RegisterSchemaResponse{
		Schema: &schemapb.Schema{
			Name:         req.Msg.GetName(),
			Version:      f.version,
			Prerelease:   req.Msg.GetPrerelease(),
			SchemaFormat: req.Msg.GetSchemaFormat(),
			SchemaBody:   req.Msg.GetSchemaBody(),
		},
	}), nil
}

func (f *fakeSchemaService) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// newSchemaNode stands up a bearer-gated SchemaService fake over httptest,
// mirroring newRegistry/newBundleNode's wiring in commands_test.go/bundle_test.go.
func newSchemaNode(t *testing.T, fake *fakeSchemaService) *httptest.Server {
	t.Helper()
	path, h := schemapbconnect.NewSchemaServiceHandler(fake)
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			http.Error(w, "missing bearer", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestSchemaRegister_HappyPath(t *testing.T) {
	fake := &fakeSchemaService{version: "2026-07-12-abcdef0123456789"}
	srv := newSchemaNode(t, fake)
	var out bytes.Buffer

	err := commands.SchemaRegister(context.Background(), env(srv, &out), commands.SchemaRegisterConfig{
		Name:       "lot-report",
		Format:     "JsonSchema",
		Body:       []byte(`{"type":"object"}`),
		Prerelease: "rc1",
	})
	if err != nil {
		t.Fatalf("SchemaRegister: %v", err)
	}
	if fake.callCount() != 1 {
		t.Fatalf("call count = %d, want 1", fake.callCount())
	}
	got := fake.calls[0]
	if got.GetName() != "lot-report" {
		t.Errorf("name = %q, want lot-report", got.GetName())
	}
	if got.GetSchemaFormat() != "JsonSchema" {
		t.Errorf("schema_format = %q, want JsonSchema", got.GetSchemaFormat())
	}
	if string(got.GetSchemaBody()) != `{"type":"object"}` {
		t.Errorf("schema_body = %q, want the input body verbatim", got.GetSchemaBody())
	}
	if got.GetPrerelease() != "rc1" {
		t.Errorf("prerelease = %q, want rc1", got.GetPrerelease())
	}
	want := "registered schema lot-report@2026-07-12-abcdef0123456789\n"
	if out.String() != want {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
}

// Registering with no prerelease passes an empty string through untouched —
// no client-side default substitution.
func TestSchemaRegister_NoPrereleasePassesEmptyString(t *testing.T) {
	fake := &fakeSchemaService{version: "v1"}
	srv := newSchemaNode(t, fake)
	err := commands.SchemaRegister(context.Background(), env(srv, &bytes.Buffer{}), commands.SchemaRegisterConfig{
		Name: "lot-report", Format: "JsonSchema", Body: []byte("{}"),
	})
	if err != nil {
		t.Fatalf("SchemaRegister: %v", err)
	}
	if got := fake.calls[0].GetPrerelease(); got != "" {
		t.Errorf("prerelease = %q, want empty", got)
	}
}

// An empty schema body (0 bytes after read) is a local usage error — no RPC
// is attempted (spec §6 Low-5).
func TestSchemaRegister_EmptyBodyRejectedLocally(t *testing.T) {
	fake := &fakeSchemaService{version: "v1"}
	srv := newSchemaNode(t, fake)
	err := commands.SchemaRegister(context.Background(), env(srv, &bytes.Buffer{}), commands.SchemaRegisterConfig{
		Name: "lot-report", Format: "JsonSchema", Body: nil,
	})
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty body: want local empty-body error, got %v", err)
	}
	if fake.callCount() != 0 {
		t.Errorf("empty body: RPC should not be attempted, calls=%d", fake.callCount())
	}
}

// An RPC-level error propagates with a non-nil error (main maps this to a
// non-zero exit); the CLI does not swallow or reword connect errors beyond
// prefixing the command name.
func TestSchemaRegister_RPCErrorPropagates(t *testing.T) {
	fake := &fakeSchemaService{err: connect.NewError(connect.CodeInvalidArgument, errors.New("bad schema_format"))}
	srv := newSchemaNode(t, fake)
	err := commands.SchemaRegister(context.Background(), env(srv, &bytes.Buffer{}), commands.SchemaRegisterConfig{
		Name: "lot-report", Format: "bogus", Body: []byte("{}"),
	})
	if err == nil || !strings.Contains(err.Error(), "bad schema_format") {
		t.Fatalf("RPC error: want the connect error surfaced, got %v", err)
	}
}
