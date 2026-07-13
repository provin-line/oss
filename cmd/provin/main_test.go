package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/cmd/provin/internal/commands"
	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	"github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
	schemapb "github.com/provin-line/oss/gen/go/dplaax/schema/v1"
	"github.com/provin-line/oss/gen/go/dplaax/schema/v1/schemapbconnect"
	"github.com/provin-line/oss/tlog/filelog"
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
		"chain get-allow no pipe":    {"chain", "get-allow"},
		"org verify no did":          {"org", "verify"},
		"org inspect no did":         {"org", "inspect"},
		"org diagnose no did":        {"org", "diagnose"},
		"org generate-txt no did":    {"org", "generate-txt"},
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
		"schema register":  {"schema", "register", "--name", "n", "--format", "f", "--file", "x", "extra"},
		"chain subscribe":  {"chain", "subscribe", "--subscriber", "s", "--publisher", "p", "extra"},
		"chain set-allow":  {"chain", "set-allow", "--pipeline", "p", "--clear", "extra"},
		"chain get-allow":  {"chain", "get-allow", "--pipeline", "p", "extra"},
		"org verify":       {"org", "verify", "--did", "did:x", "extra"},
		"org inspect":      {"org", "inspect", "--did", "did:x", "extra"},
		"org diagnose":     {"org", "diagnose", "--did", "did:x", "extra"},
		"org generate-txt": {"org", "generate-txt", "--did", "did:x", "extra"},
		"evidence rotate":  {"evidence", "rotate", "--dir", "x", "extra"},
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
		"org verify":         {"org", "verify", "--did", "did:dplaax:poc.dplaax.dev:org:acme.com"},
		"org inspect":        {"org", "inspect", "--did", "did:dplaax:poc.dplaax.dev:org:acme.com"},
		"org diagnose":       {"org", "diagnose", "--did", "did:dplaax:poc.dplaax.dev:org:acme.com"},
		"org generate-txt (no --fingerprint, needs registry)": {"org", "generate-txt", "--did", "did:dplaax:poc.dplaax.dev:org:acme.com"},
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

// exitCode is main()'s only path from a run() error to a process exit code —
// this pins all five org-verify verdict codes plus the generic-error
// fallback (spec cli-stage3-orgverify-port §7.2/§7.3), independent of os.Exit
// (which main_test.go cannot call directly).
func TestExitCode(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode int
		wantMsg  string
	}{
		{"verified (code 0)", commands.ExitStatus{Code: 0}, 0, ""},
		{"missing (code 1)", commands.ExitStatus{Code: 1}, 1, ""},
		{"invalid (code 2)", commands.ExitStatus{Code: 2}, 2, ""},
		{"unreachable (code 3)", commands.ExitStatus{Code: 3}, 3, ""},
		{"na (code 4)", commands.ExitStatus{Code: 4}, 4, ""},
		{"ExitStatus with a message is passed through", commands.ExitStatus{Code: 2, Message: "boom"}, 2, "boom"},
		{"a plain error maps to exit 1 with its own text", errors.New("connection refused"), 1, "connection refused"},
		{"a wrapped ExitStatus still unwraps (errors.As, not equality)", fmt.Errorf("org verify: %w", commands.ExitStatus{Code: 3}), 3, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, msg := exitCode(c.err)
			if code != c.wantCode {
				t.Errorf("code=%d, want %d", code, c.wantCode)
			}
			if msg != c.wantMsg {
				t.Errorf("msg=%q, want %q", msg, c.wantMsg)
			}
		})
	}
}

// orgVerifyRegistry stands up a minimal, unauthenticated W3C /did/ route
// (mirroring cmd/provin/internal/commands' own newOrgRegistry helper) so
// run()-level org tests can exercise the full CLI dispatch path without a
// DNS seam knob at the flag layer — real DNS is never touched here because
// these cases short-circuit (usage error or DID-resolution failure) before
// orgverify.Verify ever reaches its DNS lookup step.
func orgVerifyRegistry(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/did/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r) // no fixtures: every resolution attempt is a deliberate miss
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// End-to-end through run(): a non-FQDN orgId short-circuits to EndorsementNA
// before any DID or DNS I/O, so this exercises the full flag-parse ->
// commands.OrgVerify -> ExitStatus -> exitCode() chain without a DNS seam.
func TestRun_OrgVerify_NA_EndToEnd(t *testing.T) {
	srv := orgVerifyRegistry(t)
	var out bytes.Buffer
	err := run(context.Background(), []string{
		"org", "verify", "--did", "did:dplaax:poc.dplaax.dev:org:acme", // "acme": not an FQDN
		"--registry", srv.URL,
	}, strings.NewReader(""), &out)

	var es commands.ExitStatus
	if !errors.As(err, &es) {
		t.Fatalf("want commands.ExitStatus, got %T: %v", err, err)
	}
	if es.Code != 4 {
		t.Errorf("Code=%d, want 4 (na)", es.Code)
	}
	if code, _ := exitCode(err); code != 4 {
		t.Errorf("exitCode()=%d, want 4", code)
	}
	if !strings.Contains(out.String(), "endorsement: na") {
		t.Errorf("output = %q, want endorsement: na", out.String())
	}
}

// End-to-end through run(): resolving a DID the fixture registry has no
// document for is itself a verdict (EndorsementUnreachable / doc_fetch_failed
// — orgverify.Verify step 2 treats DID-Document-fetch failure as a verdict,
// not an execution error), so it flows through ExitStatus like any other
// org-verify outcome and maps to exit code 3.
func TestRun_OrgVerify_DocFetchFailure_Unreachable_EndToEnd(t *testing.T) {
	srv := orgVerifyRegistry(t)
	var out bytes.Buffer
	err := run(context.Background(), []string{
		"org", "verify", "--did", "did:dplaax:poc.dplaax.dev:org:acme.com",
		"--registry", srv.URL,
	}, strings.NewReader(""), &out)

	var es commands.ExitStatus
	if !errors.As(err, &es) {
		t.Fatalf("want commands.ExitStatus, got %T: %v", err, err)
	}
	if es.Code != 3 {
		t.Errorf("Code=%d, want 3 (unreachable)", es.Code)
	}
	if !strings.Contains(out.String(), "endorsement: unreachable") {
		t.Errorf("output = %q, want endorsement: unreachable", out.String())
	}
}

func TestRun_OrgGenerateTXT_Offline_EndToEnd(t *testing.T) {
	var out bytes.Buffer
	err := run(context.Background(), []string{
		"org", "generate-txt", "--did", "did:dplaax:poc.dplaax.dev:org:acme.com",
		"--fingerprint", "sha256:" + strings.Repeat("a", 64),
	}, strings.NewReader(""), &out)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	want := "_dplaax-org.acme.com\nv=dplaax1; did=did:dplaax:poc.dplaax.dev:org:acme.com; key=sha256:" + strings.Repeat("a", 64) + "\n"
	if out.String() != want {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
}

// evidence rotate seals a stopped evidence log into an archive segment and
// leaves a fresh empty live log — end to end through run().
func TestRun_EvidenceRotate_EndToEnd(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"e1", "e2"} {
		if _, err := l.Append(ctx, []byte(p)); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil { // release the flock: the daemon has stopped
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := run(ctx, []string{"evidence", "rotate", "--dir", dir}, strings.NewReader(""), &out); err != nil {
		t.Fatalf("evidence rotate: %v", err)
	}
	if !strings.Contains(out.String(), "rotated evidence log") || !strings.Contains(out.String(), "records:   2") {
		t.Errorf("output missing rotation summary:\n%s", out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "archive", "seg-000001", "log.ndjson")); err != nil {
		t.Errorf("archive segment not created: %v", err)
	}
	l2, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if n, _ := l2.Size(ctx); n != 0 {
		t.Errorf("live Size after rotate = %d, want 0", n)
	}
}

// evidence rotate on a directory a live opener still holds (the daemon is up)
// fails loudly rather than corrupting a running log.
func TestRun_EvidenceRotate_LockedDirFailsLoud(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l, err := filelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(ctx, []byte("e1")); err != nil {
		t.Fatal(err)
	}
	defer l.Close() // hold the flock for the whole test
	if err := run(ctx, []string{"evidence", "rotate", "--dir", dir}, strings.NewReader(""), io.Discard); err == nil {
		t.Error("evidence rotate on a locked dir: want error, got nil")
	}
}

func TestRun_EvidenceRotate_RequiresDir(t *testing.T) {
	err := run(context.Background(), []string{"evidence", "rotate"}, strings.NewReader(""), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("want required error, got %v", err)
	}
}
