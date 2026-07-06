package commands_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/cmd/provin/internal/commands"
	"github.com/provin-line/oss/cmd/provin/internal/keyfile"
	"github.com/provin-line/oss/crypto/ed25519"
	didpb "github.com/provin-line/oss/gen/go/dplaax/did/v1"
	"github.com/provin-line/oss/gen/go/dplaax/did/v1/didpbconnect"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/services/didregistry"
	didhandler "github.com/provin-line/oss/network/pkg/services/didregistry/handler"
	didyaml "github.com/provin-line/oss/network/pkg/services/didregistry/store/yamlstore"
)

const (
	registryID  = "poc.dplaax.dev"
	ownerDID    = "did:dplaax:poc.dplaax.dev:org:acme"
	pipelineDID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:lot"
	processDID  = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:lot:process:p1"
	testToken   = "cli-test-token"
)

// newRegistry stands up a real DIDService over httptest, asserting every RPC
// carries the CLI's bearer token.
func newRegistry(t *testing.T) *httptest.Server {
	t.Helper()
	svc := didregistry.New(
		didyaml.New(t.TempDir()), filestore.New(t.TempDir()),
		ed25519.Generator{}, ed25519.Verifier{}, registryID,
	)
	path, h := didpbconnect.NewDIDServiceHandler(didhandler.New(svc))
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

func env(srv *httptest.Server, out *bytes.Buffer) commands.Env {
	return commands.Env{
		Registry:   srv.URL,
		Token:      testToken,
		HTTPClient: srv.Client(),
		Stdout:     out,
	}
}

func resolve(t *testing.T, srv *httptest.Server, target string) []byte {
	t.Helper()
	c := didpbconnect.NewDIDServiceClient(srv.Client(), srv.URL)
	req := connect.NewRequest(&didpb.ResolveDIDRequest{Did: target})
	req.Header().Set("Authorization", "Bearer "+testToken)
	res, err := c.ResolveDID(context.Background(), req)
	if err != nil {
		t.Fatalf("ResolveDID(%s): %v", target, err)
	}
	return res.Msg.GetDidDocument()
}

func TestOwnerInit_RegistersAndWritesKey(t *testing.T) {
	srv := newRegistry(t)
	var out bytes.Buffer
	keyPath := filepath.Join(t.TempDir(), "acme-owner.jwk")

	if err := commands.OwnerInit(context.Background(), env(srv, &out), ownerDID, keyPath); err != nil {
		t.Fatalf("OwnerInit: %v", err)
	}
	key, err := keyfile.Load(keyPath)
	if err != nil {
		t.Fatalf("key file not written/loadable: %v", err)
	}
	if key.DID != ownerDID {
		t.Errorf("key kid = %q, want %q", key.DID, ownerDID)
	}
	if doc := resolve(t, srv, ownerDID); !strings.Contains(string(doc), ownerDID) {
		t.Errorf("resolved owner doc does not name the owner: %s", doc)
	}
	if !strings.Contains(out.String(), ownerDID) || !strings.Contains(out.String(), keyPath) {
		t.Errorf("output should name the DID and key path, got %q", out.String())
	}
}

// A retry after a partial failure (key written, registration failed) reuses the
// existing key file instead of failing on create-only — custody-first ordering
// stays recoverable.
func TestOwnerInit_ReusesExistingKeyFile(t *testing.T) {
	srv := newRegistry(t)
	keyPath := filepath.Join(t.TempDir(), "acme-owner.jwk")

	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := keyfile.Write(keyPath, ownerDID, kp.PublicKey, kp.PrivateKey); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := commands.OwnerInit(context.Background(), env(srv, &out), ownerDID, keyPath); err != nil {
		t.Fatalf("OwnerInit with pre-existing key: %v", err)
	}
	key, err := keyfile.Load(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(key.PublicKey) != string(kp.PublicKey) {
		t.Error("existing key was replaced, want reuse")
	}
}

// The key file's kid must match --did: registering DID A with DID B's key file
// is a hard error, not a silent mis-registration.
func TestOwnerInit_KidMismatchRejected(t *testing.T) {
	srv := newRegistry(t)
	keyPath := filepath.Join(t.TempDir(), "other-owner.jwk")
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := keyfile.Write(keyPath, "did:dplaax:poc.dplaax.dev:org:other", kp.PublicKey, kp.PrivateKey); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = commands.OwnerInit(context.Background(), env(srv, &out), ownerDID, keyPath)
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("kid mismatch: want refusal error, got %v", err)
	}
}

// Re-running owner init after a success (e.g. the first response was lost) is
// idempotent: each run signs a fresh proof so the registry's exact-bytes check
// answers AlreadyExists, and the CLI settles it by comparing the registered
// #signing key against the local key file — same key succeeds.
func TestOwnerInit_RerunAfterSuccessIsIdempotent(t *testing.T) {
	srv := newRegistry(t)
	keyPath := filepath.Join(t.TempDir(), "acme-owner.jwk")
	ctx := context.Background()

	var first bytes.Buffer
	if err := commands.OwnerInit(ctx, env(srv, &first), ownerDID, keyPath); err != nil {
		t.Fatalf("first OwnerInit: %v", err)
	}
	// proof.created has second resolution: a re-run within the same second
	// produces byte-identical registration (the registry's exact-hash
	// idempotency succeeds directly). Cross the second boundary to force the
	// AlreadyExists → resolve-and-compare path this test pins.
	time.Sleep(1100 * time.Millisecond)
	var second bytes.Buffer
	if err := commands.OwnerInit(ctx, env(srv, &second), ownerDID, keyPath); err != nil {
		t.Fatalf("re-run after success should be idempotent, got %v", err)
	}
	if !strings.Contains(second.String(), "already registered") {
		t.Errorf("re-run output = %q, want an already-registered notice", second.String())
	}
}

// A DID registered under someone else's key is not retryable with this key
// file: the CLI resolves, compares keys, and answers with an honest hard error
// (not a hash-conflict or a retry suggestion).
func TestOwnerInit_RegisteredUnderDifferentKeyFails(t *testing.T) {
	srv := newRegistry(t)
	ctx := context.Background()

	if err := commands.OwnerInit(ctx, env(srv, &bytes.Buffer{}), ownerDID, filepath.Join(t.TempDir(), "real.jwk")); err != nil {
		t.Fatalf("first OwnerInit: %v", err)
	}
	// A different key file claiming the same DID.
	err := commands.OwnerInit(ctx, env(srv, &bytes.Buffer{}), ownerDID, filepath.Join(t.TempDir(), "impostor.jwk"))
	if err == nil || !strings.Contains(err.Error(), "DIFFERENT key") {
		t.Fatalf("wrong-key re-init: want different-key error, got %v", err)
	}
}

func TestPipelineAndProcessCreate(t *testing.T) {
	srv := newRegistry(t)
	var out bytes.Buffer
	keyPath := filepath.Join(t.TempDir(), "acme-owner.jwk")
	ctx := context.Background()

	if err := commands.OwnerInit(ctx, env(srv, &out), ownerDID, keyPath); err != nil {
		t.Fatalf("OwnerInit: %v", err)
	}
	if err := commands.PipelineCreate(ctx, env(srv, &out), pipelineDID, keyPath); err != nil {
		t.Fatalf("PipelineCreate: %v", err)
	}
	if doc := resolve(t, srv, pipelineDID); !strings.Contains(string(doc), pipelineDID) {
		t.Errorf("resolved pipeline doc does not name the pipeline: %s", doc)
	}
	if err := commands.ProcessCreate(ctx, env(srv, &out), processDID, keyPath); err != nil {
		t.Fatalf("ProcessCreate: %v", err)
	}
	if doc := resolve(t, srv, processDID); !strings.Contains(string(doc), processDID) {
		t.Errorf("resolved process doc does not name the process: %s", doc)
	}
	if !strings.Contains(out.String(), pipelineDID) || !strings.Contains(out.String(), processDID) {
		t.Errorf("output should name issued DIDs, got %q", out.String())
	}
}

// Issuance with an unregistered owner's key fails server-side and the error
// propagates (exit non-zero for scripting).
func TestPipelineCreate_UnregisteredOwnerFails(t *testing.T) {
	srv := newRegistry(t)
	keyPath := filepath.Join(t.TempDir(), "stranger.jwk")
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := keyfile.Write(keyPath, ownerDID, kp.PublicKey, kp.PrivateKey); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = commands.PipelineCreate(context.Background(), env(srv, &out), pipelineDID, keyPath)
	if err == nil || !strings.Contains(err.Error(), "pipeline create: issue") {
		t.Fatalf("issuance with unregistered owner: want a server-side issue error, got %v", err)
	}
}
