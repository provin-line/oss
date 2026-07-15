package commands_test

import (
	"bytes"
	"context"
	stded25519 "crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/provin-line/oss/cmd/provin/internal/commands"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/orgverify"
)

// orgAcmeDID is an FQDN-orgId owner DID — distinct from commands_test.go's
// ownerDID ("...org:acme", not FQDN, N/A under NormalizeFQDN) — the org
// commands need a real FQDN to reach a DNS-driven verdict.
const orgAcmeDID = "did:dplaax:poc.dplaax.dev:org:acme.com"

// orgFakeDNS is the org commands' injectable DNS seam in tests — it never
// touches real DNS.
type orgFakeDNS struct {
	records []string
	err     error
}

func (f *orgFakeDNS) LookupTXT(context.Context, string) ([]string, error) {
	return f.records, f.err
}

// orgDoc builds a DID document whose #signing key (assertionMethod) carries
// an Ed25519 JWK for pub.
func orgDoc(id string, pub []byte) []byte {
	vm, err := did.NewMultikeyVerificationMethod(id+"#signing", id, pub)
	if err != nil {
		panic(err) // a non-Ed25519 fixture key is a test bug
	}
	doc := did.New(did.DocumentFields{
		Context:            did.IssuedDocumentContexts(),
		ID:                 id,
		Controller:         id,
		VerificationMethod: []did.VerificationMethod{vm},
		AssertionMethod:    []string{id + "#signing"},
	})
	raw, err := doc.MarshalJSON()
	if err != nil {
		panic(err) // test fixture construction; a marshal failure here is a bug in the test itself
	}
	return raw
}

// orgDIDRoutePath mirrors bundle_test.go's didRoutePath: the W3C resolution
// route the org resolver adapter targets (GET .../did/<segments>/did.json).
func orgDIDRoutePath(didStr string) string {
	rest := strings.TrimPrefix(didStr, "did:dplaax:"+registryID+":")
	return "/did/" + strings.ReplaceAll(rest, ":", "/") + "/did.json"
}

// newOrgRegistry stands up the org commands' resolution surface: an
// UNAUTHENTICATED /did/ route (spec §7.4 — public W3C resolution, no bearer
// token), serving exactly the fixture documents in docs.
func newOrgRegistry(t *testing.T, docs map[string][]byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/did/", func(w http.ResponseWriter, r *http.Request) {
		raw, ok := docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/did+json")
		_, _ = w.Write(raw)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func orgEnv(srv *httptest.Server, out *bytes.Buffer) commands.Env {
	return commands.Env{Registry: srv.URL, HTTPClient: srv.Client(), Stdout: out}
}

func mustEd25519Key(t *testing.T) []byte {
	t.Helper()
	pub, _, err := stded25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func mustFingerprint(t *testing.T, docBytes []byte) string {
	t.Helper()
	var doc did.DIDDocument
	if err := doc.UnmarshalJSON(docBytes); err != nil {
		t.Fatalf("unmarshal fixture doc: %v", err)
	}
	fp, err := orgverify.FingerprintFromDIDDocument(&doc)
	if err != nil {
		t.Fatalf("fingerprint fixture doc: %v", err)
	}
	return fp
}

func TestOrgVerify_Verified(t *testing.T) {
	pub := mustEd25519Key(t)
	docBytes := orgDoc(orgAcmeDID, pub)
	fp := mustFingerprint(t, docBytes)
	srv := newOrgRegistry(t, map[string][]byte{orgDIDRoutePath(orgAcmeDID): docBytes})
	var out bytes.Buffer

	err := commands.OrgVerify(context.Background(), orgEnv(srv, &out), commands.OrgVerifyConfig{
		DID:         orgAcmeDID,
		DNSResolver: &orgFakeDNS{records: []string{"v=dplaax1; did=" + orgAcmeDID + "; key=" + fp}},
	})
	if err != nil {
		t.Fatalf("OrgVerify: %v", err)
	}
	if !strings.Contains(out.String(), "endorsement: verified") {
		t.Errorf("output = %q, want endorsement: verified", out.String())
	}
}

func TestOrgVerify_Missing_ExitCode1(t *testing.T) {
	pub := mustEd25519Key(t)
	docBytes := orgDoc(orgAcmeDID, pub)
	srv := newOrgRegistry(t, map[string][]byte{orgDIDRoutePath(orgAcmeDID): docBytes})
	var out bytes.Buffer

	err := commands.OrgVerify(context.Background(), orgEnv(srv, &out), commands.OrgVerifyConfig{
		DID:         orgAcmeDID,
		DNSResolver: &orgFakeDNS{err: orgverify.ErrDNSNoRecords},
	})
	assertExitStatus(t, err, 1)
	if !strings.Contains(out.String(), "endorsement: missing") {
		t.Errorf("output = %q, want endorsement: missing", out.String())
	}
}

func TestOrgVerify_Invalid_ExitCode2(t *testing.T) {
	pub := mustEd25519Key(t)
	docBytes := orgDoc(orgAcmeDID, pub)
	srv := newOrgRegistry(t, map[string][]byte{orgDIDRoutePath(orgAcmeDID): docBytes})
	var out bytes.Buffer

	wrongFP := mustFingerprint(t, orgDoc(orgAcmeDID, mustEd25519Key(t)))
	err := commands.OrgVerify(context.Background(), orgEnv(srv, &out), commands.OrgVerifyConfig{
		DID:         orgAcmeDID,
		DNSResolver: &orgFakeDNS{records: []string{"v=dplaax1; did=" + orgAcmeDID + "; key=" + wrongFP}},
	})
	assertExitStatus(t, err, 2)
	if !strings.Contains(out.String(), "endorsement: invalid") {
		t.Errorf("output = %q, want endorsement: invalid", out.String())
	}
}

func TestOrgVerify_Unreachable_ExitCode3(t *testing.T) {
	pub := mustEd25519Key(t)
	docBytes := orgDoc(orgAcmeDID, pub)
	srv := newOrgRegistry(t, map[string][]byte{orgDIDRoutePath(orgAcmeDID): docBytes})
	var out bytes.Buffer

	err := commands.OrgVerify(context.Background(), orgEnv(srv, &out), commands.OrgVerifyConfig{
		DID:         orgAcmeDID,
		DNSResolver: &orgFakeDNS{err: orgverify.ErrDNSTimeout},
	})
	assertExitStatus(t, err, 3)
	if !strings.Contains(out.String(), "endorsement: unreachable") {
		t.Errorf("output = %q, want endorsement: unreachable", out.String())
	}
}

func TestOrgVerify_NA_ExitCode4(t *testing.T) {
	// orgId "acme" (no dot) is not an FQDN; NormalizeFQDN short-circuits
	// before any DID resolution is attempted, but --registry is still
	// required up front (spec §3: verify always needs registry resolution).
	srv := newOrgRegistry(t, map[string][]byte{})
	var out bytes.Buffer

	err := commands.OrgVerify(context.Background(), orgEnv(srv, &out), commands.OrgVerifyConfig{
		DID:         ownerDID, // "did:dplaax:poc.dplaax.dev:org:acme" from commands_test.go
		DNSResolver: &orgFakeDNS{},
	})
	assertExitStatus(t, err, 4)
	if !strings.Contains(out.String(), "endorsement: na") {
		t.Errorf("output = %q, want endorsement: na", out.String())
	}
}

func TestOrgVerify_RequiresRegistry(t *testing.T) {
	var out bytes.Buffer
	err := commands.OrgVerify(context.Background(), commands.Env{Stdout: &out}, commands.OrgVerifyConfig{DID: orgAcmeDID})
	if err == nil || !strings.Contains(err.Error(), "--registry is required") {
		t.Fatalf("want registry-required usage error, got %v", err)
	}
	var es commands.ExitStatus
	if errors.As(err, &es) {
		t.Fatalf("registry-required usage error must NOT be an ExitStatus (it's not a verdict), got %+v", es)
	}
}

// Inspect never computes a verdict: it exits 0 (err == nil) even when the
// underlying state is exactly what would be a negative Verify() outcome.
func TestOrgInspect_AlwaysSucceedsOnNegativeState(t *testing.T) {
	pub := mustEd25519Key(t)
	docBytes := orgDoc(orgAcmeDID, pub)
	srv := newOrgRegistry(t, map[string][]byte{orgDIDRoutePath(orgAcmeDID): docBytes})
	var out bytes.Buffer

	err := commands.OrgInspect(context.Background(), orgEnv(srv, &out), commands.OrgInspectConfig{
		DID:         orgAcmeDID,
		DNSResolver: &orgFakeDNS{err: orgverify.ErrDNSNoRecords},
	})
	if err != nil {
		t.Fatalf("OrgInspect must exit 0 (no verdict), got err: %v", err)
	}
	if !strings.Contains(out.String(), orgAcmeDID) {
		t.Errorf("output = %q, want the DID named", out.String())
	}
}

// Diagnose exits 0 even on a negative verdict; its product is remediation
// steps, not a pass/fail judgment (spec §7.7).
func TestOrgDiagnose_AlwaysSucceedsOnNegativeVerdict(t *testing.T) {
	pub := mustEd25519Key(t)
	docBytes := orgDoc(orgAcmeDID, pub)
	srv := newOrgRegistry(t, map[string][]byte{orgDIDRoutePath(orgAcmeDID): docBytes})
	var out bytes.Buffer

	err := commands.OrgDiagnose(context.Background(), orgEnv(srv, &out), commands.OrgDiagnoseConfig{
		DID:         orgAcmeDID,
		DNSResolver: &orgFakeDNS{err: orgverify.ErrDNSNoRecords},
	})
	if err != nil {
		t.Fatalf("OrgDiagnose must exit 0 regardless of verdict, got err: %v", err)
	}
	if !strings.Contains(out.String(), "endorsement: missing") {
		t.Errorf("output = %q, want the verdict reported", out.String())
	}
	if !strings.Contains(out.String(), "remediation steps") {
		t.Errorf("output = %q, want remediation steps", out.String())
	}
}

func TestOrgGenerateTXT_Online(t *testing.T) {
	pub := mustEd25519Key(t)
	docBytes := orgDoc(orgAcmeDID, pub)
	fp := mustFingerprint(t, docBytes)
	srv := newOrgRegistry(t, map[string][]byte{orgDIDRoutePath(orgAcmeDID): docBytes})
	var out bytes.Buffer

	err := commands.OrgGenerateTXT(context.Background(), orgEnv(srv, &out), commands.OrgGenerateTXTConfig{DID: orgAcmeDID})
	if err != nil {
		t.Fatalf("OrgGenerateTXT: %v", err)
	}
	want := "_dplaax-org.acme.com\nv=dplaax1; did=" + orgAcmeDID + "; key=" + fp + "\n"
	if out.String() != want {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
}

// --fingerprint skips DID resolution entirely: no --registry is needed, and
// no HTTP call is made (the test passes an empty Env with no server at all —
// any accidental network attempt would error, not silently succeed).
func TestOrgGenerateTXT_OfflineFingerprint(t *testing.T) {
	fp := "sha256:" + strings.Repeat("a", 64)
	var out bytes.Buffer

	err := commands.OrgGenerateTXT(context.Background(), commands.Env{Stdout: &out}, commands.OrgGenerateTXTConfig{
		DID:         orgAcmeDID,
		Fingerprint: fp,
	})
	if err != nil {
		t.Fatalf("OrgGenerateTXT (offline): %v", err)
	}
	want := "_dplaax-org.acme.com\nv=dplaax1; did=" + orgAcmeDID + "; key=" + fp + "\n"
	if out.String() != want {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
}

func TestOrgGenerateTXT_RequiresRegistryWhenNoFingerprint(t *testing.T) {
	var out bytes.Buffer
	err := commands.OrgGenerateTXT(context.Background(), commands.Env{Stdout: &out}, commands.OrgGenerateTXTConfig{DID: orgAcmeDID})
	if err == nil || !strings.Contains(err.Error(), "--registry is required") {
		t.Fatalf("want registry-required usage error, got %v", err)
	}
}

// A pipeline-level DID is normalized to its owner for the TXT record's did=
// value — the level Verify() actually compares against. Generating a record
// with the raw pipeline DID would never validate.
func TestOrgGenerateTXT_NormalizesToOwnerDID(t *testing.T) {
	pipelineDID := orgAcmeDID + ":pipeline:lot"
	fp := "sha256:" + strings.Repeat("a", 64)
	var out bytes.Buffer

	err := commands.OrgGenerateTXT(context.Background(), commands.Env{Stdout: &out}, commands.OrgGenerateTXTConfig{
		DID:         pipelineDID,
		Fingerprint: fp,
	})
	if err != nil {
		t.Fatalf("OrgGenerateTXT: %v", err)
	}
	if strings.Contains(out.String(), "pipeline") {
		t.Errorf("output = %q, must name the OWNER DID, not the pipeline DID", out.String())
	}
	if !strings.Contains(out.String(), "did="+orgAcmeDID+";") {
		t.Errorf("output = %q, want did=%s", out.String(), orgAcmeDID)
	}
}

// assertExitStatus fails the test unless err is a commands.ExitStatus with
// exactly wantCode.
func assertExitStatus(t *testing.T, err error, wantCode int) {
	t.Helper()
	var es commands.ExitStatus
	if !errors.As(err, &es) {
		t.Fatalf("want commands.ExitStatus, got %T: %v", err, err)
	}
	if es.Code != wantCode {
		t.Errorf("ExitStatus.Code=%d, want %d", es.Code, wantCode)
	}
}

// The resolver adapter enforces document identity (the resolver.Resolver
// contract): a registry answering the resolution route with a DIFFERENT
// identity's document is rejected before fingerprinting — a matching TXT
// record must never yield a false `verified` (Codex P1). Per spec §7.6 the
// rejected resolve then surfaces as the Unreachable VERDICT (exit 3), the
// same fail-closed classification as any other document-retrieval failure.
func TestOrgVerify_RegistryIdentityMismatch_FailsClosed(t *testing.T) {
	pub := mustEd25519Key(t)
	imposter := orgDoc("did:dplaax:"+registryID+":org:mallory.example", pub)
	fp := mustFingerprint(t, imposter)
	// The route for acme serves mallory's document, and the TXT record
	// endorses mallory's key under acme's DID — the exact false-verified setup.
	srv := newOrgRegistry(t, map[string][]byte{orgDIDRoutePath(orgAcmeDID): imposter})
	var out bytes.Buffer

	err := commands.OrgVerify(context.Background(), orgEnv(srv, &out), commands.OrgVerifyConfig{
		DID:         orgAcmeDID,
		DNSResolver: &orgFakeDNS{records: []string{"v=dplaax1; did=" + orgAcmeDID + "; key=" + fp}},
	})
	assertExitStatus(t, err, 3)
	if !strings.Contains(out.String(), "endorsement: unreachable") {
		t.Errorf("output = %q, want endorsement: unreachable", out.String())
	}
	if strings.Contains(out.String(), "endorsement: verified") {
		t.Errorf("mismatched document produced a verified verdict: %q", out.String())
	}
}

// The FQDN gate runs BEFORE any resolution in generate-txt: a non-FQDN orgId
// fails with the FQDN error even when no registry is configured at all —
// proof no network work precedes the gate.
func TestOrgGenerateTXT_NonFQDNOrgID_FailsBeforeResolution(t *testing.T) {
	var out bytes.Buffer
	err := commands.OrgGenerateTXT(context.Background(), commands.Env{Stdout: &out}, commands.OrgGenerateTXTConfig{
		DID: "did:dplaax:poc.dplaax.dev:org:acme",
	})
	if err == nil || !strings.Contains(err.Error(), "not an FQDN") {
		t.Fatalf("want FQDN gate error before any resolution, got %v", err)
	}
}
