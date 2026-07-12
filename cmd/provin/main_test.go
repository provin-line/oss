package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"

	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	"github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
	schemapb "github.com/provin-line/oss/gen/go/dplaax/schema/v1"
	"github.com/provin-line/oss/gen/go/dplaax/schema/v1/schemapbconnect"
)

func TestRun_UnknownOrMissingCommand(t *testing.T) {
	for name, args := range map[string][]string{
		"no args":       {},
		"group only":    {"owner"},
		"unknown group": {"frobnicate", "now"},
		"unknown op":    {"owner", "destroy"},
	} {
		t.Run(name, func(t *testing.T) {
			err := run(context.Background(), args, strings.NewReader(""), io.Discard)
			if err == nil || !strings.Contains(err.Error(), "usage:") {
				t.Fatalf("want usage error, got %v", err)
			}
		})
	}
}

func TestRun_RequiredFlags(t *testing.T) {
	for name, args := range map[string][]string{
		"owner init no did":          {"owner", "init", "--key", "k.jwk"},
		"owner init no key":          {"owner", "init", "--did", "did:x"},
		"pipeline create no did":     {"pipeline", "create", "--owner-key", "k.jwk"},
		"process create no owner":    {"process", "create", "--did", "did:x"},
		"schema register no name":    {"schema", "register", "--format", "f", "--file", "x"},
		"schema register no format":  {"schema", "register", "--name", "n", "--file", "x"},
		"schema register no file":    {"schema", "register", "--name", "n", "--format", "f"},
		"chain subscribe no subscr":  {"chain", "subscribe", "--publisher", "p"},
		"chain subscribe no publish": {"chain", "subscribe", "--subscriber", "s"},
		"chain set-allow no pipe":    {"chain", "set-allow", "--pattern", "p"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(context.Background(), args, strings.NewReader(""), io.Discard); err == nil || !strings.Contains(err.Error(), "required") {
				t.Fatalf("want required-flag error, got %v", err)
			}
		})
	}
}

// Unexpected positional arguments after flags are a usage error for the
// three new commands (spec §6 Low-5) — checked before any required-flag or
// file-read work, so a stray argument is caught even if other flags would
// otherwise be enough to proceed.
func TestRun_UnexpectedPositionalArgs(t *testing.T) {
	for name, args := range map[string][]string{
		"schema register": {"schema", "register", "--name", "n", "--format", "f", "--file", "x", "extra"},
		"chain subscribe": {"chain", "subscribe", "--subscriber", "s", "--publisher", "p", "extra"},
		"chain set-allow": {"chain", "set-allow", "--pipeline", "p", "--clear", "extra"},
	} {
		t.Run(name, func(t *testing.T) {
			err := run(context.Background(), args, strings.NewReader(""), io.Discard)
			if err == nil || !strings.Contains(err.Error(), "unexpected arguments") {
				t.Fatalf("want unexpected-arguments usage error, got %v", err)
			}
		})
	}
}

// A blank --pattern value is rejected at flag-parse time (before any
// required-flag check or RPC attempt) — an empty glob is never a meaningful
// allow-list entry.
func TestRun_ChainSetAllow_BlankPatternIsUsageError(t *testing.T) {
	err := run(context.Background(), []string{"chain", "set-allow", "--pipeline", "p", "--pattern", ""}, strings.NewReader(""), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "blank") {
		t.Fatalf("blank pattern: want usage error, got %v", err)
	}
}

// A malformed registry URL fails closed before any network I/O (the client
// validates the base URL); PROVIN_REGISTRY feeds the flag default. Covers
// every client constructor family the CLI uses (DID, Schema, Chain).
func TestRun_RegistryURLValidatedFromEnv(t *testing.T) {
	schemaFile := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(schemaFile, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"owner (DID client)": {"owner", "init", "--did", "did:dplaax:poc.dplaax.dev:org:acme", "--key", filepath.Join(t.TempDir(), "owner.jwk")},
		"schema register":    {"schema", "register", "--name", "n", "--format", "f", "--file", schemaFile},
		"chain subscribe":    {"chain", "subscribe", "--subscriber", "s", "--publisher", "p"},
		"chain set-allow":    {"chain", "set-allow", "--pipeline", "p", "--clear"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("PROVIN_REGISTRY", "not-a-url")
			t.Setenv("PROVIN_TOKEN", "tok")
			err := run(context.Background(), args, strings.NewReader(""), io.Discard)
			if err == nil || !strings.Contains(err.Error(), "registry URL") {
				t.Fatalf("want registry-URL validation error, got %v", err)
			}
		})
	}
}

// stdinFakeChain is a minimal ChainService fake, local to main_test.go, for
// the one boundary only the flag layer owns: an EXPLICIT `--delivery ""`
// must behave exactly like an omitted flag (spec §6 Low-5) — empty on the
// wire, "(protocol default)" in the output.
type stdinFakeChain struct {
	chainpbconnect.UnimplementedChainServiceHandler
	gotDelivery string
}

func (f *stdinFakeChain) Subscribe(_ context.Context, req *connect.Request[chainpb.SubscribeRequest]) (*connect.Response[chainpb.SubscribeResponse], error) {
	f.gotDelivery = req.Msg.GetPayloadDelivery()
	return connect.NewResponse(&chainpb.SubscribeResponse{SubscriptionId: "sub-test"}), nil
}

func TestRun_ChainSubscribe_ExplicitEmptyDeliveryBehavesAsOmitted(t *testing.T) {
	fake := &stdinFakeChain{}
	path, h := chainpbconnect.NewChainServiceHandler(fake)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	var out bytes.Buffer
	err := run(context.Background(), []string{
		"chain", "subscribe", "--subscriber", "did:s", "--publisher", "did:p",
		"--delivery", "",
		"--registry", srv.URL, "--token", "t",
	}, strings.NewReader(""), &out)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if fake.gotDelivery != "" {
		t.Errorf("explicit --delivery \"\" put %q on the wire, want empty", fake.gotDelivery)
	}
	if !strings.Contains(out.String(), "by-reference (protocol default)") {
		t.Errorf("output = %q, want the protocol-default wording", out.String())
	}
}

// stdinFakeSchema is a minimal SchemaService fake, local to main_test.go,
// that exercises `schema register --file -` end-to-end through run() — the
// stdin-reading plumbing that only main.go owns (cmd/provin/internal/commands
// receives an already-read []byte body, per its config-struct convention).
type stdinFakeSchema struct {
	schemapbconnect.UnimplementedSchemaServiceHandler
	gotBody []byte
}

func (f *stdinFakeSchema) RegisterSchema(_ context.Context, req *connect.Request[schemapb.RegisterSchemaRequest]) (*connect.Response[schemapb.RegisterSchemaResponse], error) {
	f.gotBody = req.Msg.GetSchemaBody()
	return connect.NewResponse(&schemapb.RegisterSchemaResponse{
		Schema: &schemapb.Schema{Name: req.Msg.GetName(), Version: "v-test"},
	}), nil
}

func TestRun_SchemaRegister_FileDashReadsStdin(t *testing.T) {
	fake := &stdinFakeSchema{}
	path, h := schemapbconnect.NewSchemaServiceHandler(fake)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	stdin := strings.NewReader(`{"type":"object"}`)
	var out bytes.Buffer
	err := run(context.Background(), []string{
		"schema", "register",
		"--name", "lot-report", "--format", "JsonSchema", "--file", "-",
		"--registry", srv.URL, "--token", "t",
	}, stdin, &out)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if string(fake.gotBody) != `{"type":"object"}` {
		t.Errorf("stdin body not read through: got %q", fake.gotBody)
	}
	if !strings.Contains(out.String(), "registered schema lot-report@v-test") {
		t.Errorf("output = %q", out.String())
	}
}

// An empty schema body (0 bytes after --file is read) is a local usage
// error — checked before any RPC is attempted, so no --registry/--token are
// needed for this case to fail correctly.
func TestRun_SchemaRegister_EmptyBodyIsUsageError(t *testing.T) {
	emptyFile := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(emptyFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := run(context.Background(), []string{
		"schema", "register", "--name", "n", "--format", "f", "--file", emptyFile,
	}, strings.NewReader(""), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "schema body must not be empty") {
		t.Fatalf("empty body: want the local empty-body error, got %v", err)
	}
}
