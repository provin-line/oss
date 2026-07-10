// Tranche 1 of the dplaax conformance harness: the pure-function families of
// the spec's vector catalog (vendored byte-exact under vectors/dplaax/) run
// against the implementation in CI, so the catalog and the code cannot drift
// apart unnoticed. Behavioral families needing fixture drivers (chain.trigger
// issuance, process, audit attribution, registry/resolver sequences) are
// tranche 2 — see README.md.
package conformance_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/canon/jcs"
	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/delegation"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

const dplaaxVectorDir = "vectors/dplaax"

// TestDplaaxVendoredManifest pins the vendored copies byte-exact: every file
// listed in MANIFEST.sha256 must exist with that hash, and no unlisted vector
// may appear. Re-sync deliberately with scripts/sync-spec-vectors.sh — an
// in-place edit of a vendored vector is a drift bug, never a fix.
func TestDplaaxVendoredManifest(t *testing.T) {
	manifest, err := os.ReadFile(filepath.Join(dplaaxVectorDir, "MANIFEST.sha256"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	listed := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(manifest)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("malformed manifest line %q", line)
		}
		wantHex, name := fields[0], strings.TrimPrefix(fields[1], "*")
		listed[name] = true
		data, err := os.ReadFile(filepath.Join(dplaaxVectorDir, name))
		if err != nil {
			t.Errorf("manifest lists %s but it is unreadable: %v", name, err)
			continue
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != wantHex {
			t.Errorf("%s: sha256 = %s, want %s (vendored copy edited in place?)", name, got, wantHex)
		}
	}
	files, err := filepath.Glob(filepath.Join(dplaaxVectorDir, "*.json"))
	if err != nil {
		t.Fatalf("glob vendored vectors: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no vendored vectors found")
	}
	for _, f := range files {
		if name := filepath.Base(f); !listed[name] {
			t.Errorf("%s is not in MANIFEST.sha256 (sync script regenerates it)", name)
		}
	}
}

// dplaaxVector is the generic catalog shape; family drivers re-parse Input and
// Expect into their concrete forms.
type dplaaxVector struct {
	ID          string          `json:"id"`
	Rule        string          `json:"rule"`
	Description string          `json:"description"`
	Input       json.RawMessage `json:"input"`
	Expect      json.RawMessage `json:"expect"`
}

func loadDplaax(t *testing.T, id string) dplaaxVector {
	t.Helper()
	var v dplaaxVector
	loadVector(t, filepath.Join(dplaaxVectorDir, id+".json"), &v)
	if v.ID != id {
		t.Fatalf("vector id %q != file %q", v.ID, id)
	}
	return v
}

func expectString(t *testing.T, v dplaaxVector) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(v.Expect, &s); err != nil {
		t.Fatalf("%s: expect is not a string: %v", v.ID, err)
	}
	return s
}

func expectConfidence(t *testing.T, v dplaaxVector) vc.ConfidenceState {
	t.Helper()
	var e struct {
		Confidence string `json:"confidence"`
	}
	if err := json.Unmarshal(v.Expect, &e); err != nil {
		t.Fatalf("%s: expect: %v", v.ID, err)
	}
	return stateFromName(t, v.ID, e.Confidence)
}

func stateFromName(t *testing.T, id, name string) vc.ConfidenceState {
	t.Helper()
	switch name {
	case "failed":
		return vc.ConfidenceFailed
	case "indeterminate":
		return vc.ConfidenceIndeterminate
	case "verified":
		return vc.ConfidenceVerified
	}
	t.Fatalf("%s: unknown confidence state %q", id, name)
	return 0
}

// --- canon family: strict decoding + JCS canonicalization ---

func TestDplaaxCanonVectors(t *testing.T) {
	for i := 1; i <= 8; i++ {
		v := loadDplaax(t, vecID("canon", i))
		t.Run(v.ID, func(t *testing.T) {
			var input struct {
				Document    string `json:"document"`
				DocumentB64 string `json:"document_b64"`
			}
			if err := json.Unmarshal(v.Input, &input); err != nil {
				t.Fatalf("input: %v", err)
			}
			doc := []byte(input.Document)
			if input.DocumentB64 != "" {
				var err error
				if doc, err = base64.StdEncoding.DecodeString(input.DocumentB64); err != nil {
					t.Fatalf("decode document_b64: %v", err)
				}
			}
			var parsed any
			decodeErr := canon.NewStrictDecoder(doc).Decode(&parsed)

			var e struct {
				Canonical string `json:"canonical"`
			}
			if err := json.Unmarshal(v.Expect, &e); err == nil && e.Canonical != "" {
				if decodeErr != nil {
					t.Fatalf("strict decode rejected an accept vector: %v", decodeErr)
				}
				got, err := jcs.Canonicalize(parsed)
				if err != nil {
					t.Fatalf("Canonicalize: %v", err)
				}
				if string(got) != e.Canonical {
					t.Errorf("canonical = %s, want %s", got, e.Canonical)
				}
				return
			}
			if expectString(t, v) != "reject" {
				t.Fatalf("unhandled expect %s", v.Expect)
			}
			if decodeErr == nil {
				t.Error("strict decode accepted a reject vector")
			}
		})
	}
}

// --- cred family: receiver wire-form contract ---
//
// Two stages, both the REAL receive path: the strict credential decode, then
// ValidateWireForm — the single implementation the data-integrity axis
// delegates to. Proof POLICY (extra members, signatures) is deliberately not
// part of this family's verdict: cred-020 pins that an unknown proof member is
// accepted as-received at wire-form level (the signer-authenticity axis owns
// what a verifier honours).
func TestDplaaxCredVectors(t *testing.T) {
	for i := 1; i <= 32; i++ {
		v := loadDplaax(t, vecID("cred", i))
		t.Run(v.ID, func(t *testing.T) {
			var input struct {
				Credential json.RawMessage `json:"credential"`
			}
			if err := json.Unmarshal(v.Input, &input); err != nil {
				t.Fatalf("input: %v", err)
			}
			want := expectString(t, v)
			var cred vc.PipelinePassCredential
			if err := cred.UnmarshalJSON(input.Credential); err != nil {
				if want != "reject" {
					t.Errorf("decode rejected an accept vector: %v", err)
				}
				return
			}
			err := cred.ValidateWireForm()
			switch want {
			case "accept":
				if err != nil {
					t.Errorf("ValidateWireForm rejected an accept vector: %v", err)
				}
			case "reject":
				if err == nil {
					t.Error("ValidateWireForm accepted a reject vector")
				}
			default:
				t.Fatalf("unhandled expect %q", want)
			}
		})
	}
}

// --- process family: sink receipt wire-form (process-005) ---
//
// process.sink.receipt: a Sink Process's delivery receipt is a well-formed
// PipelinePassCredential that references the last upstream credential via
// previousCredential. This exercises the same receive-path wire contract as the
// cred family (decode + ValidateWireForm) plus the receipt's identity shape —
// transformationClaim provin:sink-receipt with inputHash == outputHash (a receipt
// transforms nothing). Enabled by the ClaimSinkReceipt registration (this slice).
//
// process-004 (process.sink.verify — a sink must not terminate without verifying)
// is an op-SEQUENCE rule; its driver needs an instrumented sink fixture and lands
// with the tranche-2 conformance registry (gap-backlog). The runtime guarantee is
// pinned in pipeline/sink (a sink always verifies before writing).
func TestDplaaxProcessSinkReceipt(t *testing.T) {
	v := loadDplaax(t, "process-005")
	var input struct {
		Credential json.RawMessage `json:"credential"`
	}
	if err := json.Unmarshal(v.Input, &input); err != nil {
		t.Fatalf("input: %v", err)
	}
	if want := expectString(t, v); want != "accept" {
		t.Fatalf("process-005 expect = %q, want accept", want)
	}
	var cred vc.PipelinePassCredential
	if err := cred.UnmarshalJSON(input.Credential); err != nil {
		t.Fatalf("receipt decode: %v", err)
	}
	if err := cred.ValidateWireForm(); err != nil {
		t.Fatalf("receipt ValidateWireForm rejected an accept vector: %v", err)
	}
	subject, err := cred.Subject()
	if err != nil {
		t.Fatalf("receipt subject: %v", err)
	}
	if subject.TransformationClaim != vc.ClaimSinkReceipt {
		t.Errorf("transformationClaim = %q, want %q", subject.TransformationClaim, vc.ClaimSinkReceipt)
	}
	if cred.PreviousCredential() == "" {
		t.Error("receipt has no previousCredential (must reference the consumed credential)")
	}
	if subject.InputHash != subject.OutputHash {
		t.Errorf("receipt inputHash %q != outputHash %q (a receipt transforms nothing)", subject.InputHash, subject.OutputHash)
	}
}

// --- commitment family ---

func TestDplaaxCommitmentVectors(t *testing.T) {
	verifier := vc.NewVerifier(local.New(), ed25519.Verifier{})
	for i := 1; i <= 13; i++ {
		v := loadDplaax(t, vecID("commitment", i))
		t.Run(v.ID, func(t *testing.T) {
			switch i {
			case 1, 3, 4: // wire-form shape of the commitment attributes
				var input struct {
					Credential json.RawMessage `json:"credential"`
				}
				mustParse(t, v.Input, &input)
				var cred vc.PipelinePassCredential
				if err := cred.UnmarshalJSON(input.Credential); err != nil {
					if expectString(t, v) != "reject" {
						t.Errorf("decode rejected an accept vector: %v", err)
					}
					return
				}
				err := cred.ValidateWireForm()
				if want := expectString(t, v); (err == nil) != (want == "accept") {
					t.Errorf("ValidateWireForm err=%v, want %s", err, want)
				}
			case 2: // all-consumed: predecessor's issuer must be in derived_from
				var input struct {
					Credential  json.RawMessage `json:"credential"`
					Predecessor json.RawMessage `json:"predecessor"`
				}
				mustParse(t, v.Input, &input)
				pred := mustCred(t, input.Predecessor)
				cred := mustCred(t, input.Credential)
				res, err := verifier.VerifyChain(context.Background(), []*vc.PipelinePassCredential{pred, cred})
				if err != nil {
					t.Fatalf("VerifyChain: %v", err)
				}
				want := expectString(t, v)
				if got := res.Axes.DataIntegrity == vc.ConfidenceVerified; got != (want == "accept") {
					t.Errorf("DataIntegrity=%v, want %s", res.Axes.DataIntegrity, want)
				}
			case 5, 6, 7: // construction: sources -> commitment
				var input struct {
					Sources             []json.RawMessage `json:"sources"`
					SourceRootCanonical string            `json:"source_root_canonical"`
				}
				mustParse(t, v.Input, &input)
				sources := make([]*vc.PipelinePassCredential, len(input.Sources))
				for j, raw := range input.Sources {
					sources[j] = mustCred(t, raw)
				}
				sc, err := vc.NewSourceCommitment(sources, input.SourceRootCanonical)
				if err != nil {
					t.Fatalf("NewSourceCommitment: %v", err)
				}
				var e struct {
					DerivedFrom         []string `json:"derived_from"`
					SourceRoot          string   `json:"source_root"`
					SourceRootCanonical string   `json:"source_root_canonical"`
				}
				mustParse(t, v.Expect, &e)
				if len(sc.DerivedFrom) != len(e.DerivedFrom) {
					t.Fatalf("derived_from = %v, want %v", sc.DerivedFrom, e.DerivedFrom)
				}
				for j := range e.DerivedFrom {
					if sc.DerivedFrom[j] != e.DerivedFrom[j] {
						t.Errorf("derived_from[%d] = %q, want %q", j, sc.DerivedFrom[j], e.DerivedFrom[j])
					}
				}
				if sc.SourceRoot != e.SourceRoot {
					t.Errorf("source_root = %s, want %s", sc.SourceRoot, e.SourceRoot)
				}
				if sc.SourceRootCanonical != e.SourceRootCanonical {
					t.Errorf("source_root_canonical = %s, want %s", sc.SourceRootCanonical, e.SourceRootCanonical)
				}
			case 8, 9, 10, 11, 13: // verification: credential + gathered sources -> confidence (13 = the verified positive path)
				var input struct {
					Credential json.RawMessage   `json:"credential"`
					Sources    []json.RawMessage `json:"sources"`
				}
				mustParse(t, v.Input, &input)
				sources := make([]*vc.PipelinePassCredential, len(input.Sources))
				for j, raw := range input.Sources {
					sources[j] = mustCred(t, raw)
				}
				got, sErr := verifier.VerifySourceCommitment(context.Background(), mustCred(t, input.Credential), sources)
				if sErr != nil {
					// Advisory in the API contract, but visible here so a
					// driver-side parse defect cannot silently satisfy a
					// failed-expectation (review note).
					t.Logf("VerifySourceCommitment advisory error: %v", sErr)
				}
				if want := expectConfidence(t, v); got != want {
					t.Errorf("VerifySourceCommitment = %v, want %v", got, want)
				}
			case 12:
				t.Skip("commitment-012 needs a durable VC store (restart persistence) — tranche 2, durable-stores epic")
			}
		})
	}
}

// --- chain family, verify-side (data-flow continuity) ---
//
// chain-001..005 exercise ISSUANCE behavior (trigger classification) and are
// tranche 2; 006..008 are chain verification and run against the real
// VerifyChain. The fixtures carry synthetic proofs, so only the resolver-free
// DataIntegrity axis carries the verdict (continuity, linkage, origin rule).
func TestDplaaxChainContinuityVectors(t *testing.T) {
	verifier := vc.NewVerifier(local.New(), ed25519.Verifier{})
	for i := 6; i <= 8; i++ {
		v := loadDplaax(t, vecID("chain", i))
		t.Run(v.ID, func(t *testing.T) {
			var input struct {
				Chain []json.RawMessage `json:"chain"`
			}
			mustParse(t, v.Input, &input)
			chain := make([]*vc.PipelinePassCredential, len(input.Chain))
			for j, raw := range input.Chain {
				chain[j] = mustCred(t, raw)
			}
			res, err := verifier.VerifyChain(context.Background(), chain)
			if err != nil {
				t.Fatalf("VerifyChain: %v", err)
			}
			want := expectString(t, v)
			if got := res.Axes.DataIntegrity == vc.ConfidenceVerified; got != (want == "accept") {
				t.Errorf("DataIntegrity=%v, want %s", res.Axes.DataIntegrity, want)
			}
		})
	}
}

// --- confidence family ---

func TestDplaaxConfidenceSynthesisVectors(t *testing.T) {
	for i := 1; i <= 3; i++ {
		v := loadDplaax(t, vecID("confidence", i))
		t.Run(v.ID, func(t *testing.T) {
			var input struct {
				Axes map[string]string `json:"axes"`
			}
			mustParse(t, v.Input, &input)
			axes := vc.AxisResult{
				SignerAuthenticity: stateFromName(t, v.ID, input.Axes["signer-authenticity"]),
				ChainConsistency:   stateFromName(t, v.ID, input.Axes["chain-consistency"]),
				DataIntegrity:      stateFromName(t, v.ID, input.Axes["data-integrity"]),
			}
			if got, want := vc.EvaluateConfidence(axes), expectConfidence(t, v); got != want {
				t.Errorf("EvaluateConfidence = %v, want %v", got, want)
			}
		})
	}
}

// entriesRegistry is the lifecycle-registry fixture: PhaseAt resolves the
// latest entry for id whose effectiveDate is at or before t (the registry
// semantics of confidence.cryptosuite-lifecycle); no entry means Unknown.
type entriesRegistry struct {
	entries []registryEntry
}

type registryEntry struct {
	ID            string
	Phase         vc.LifecyclePhase
	EffectiveDate time.Time
}

func (r entriesRegistry) PhaseAt(_ context.Context, id string, t time.Time) (vc.LifecyclePhase, error) {
	phase := vc.PhaseUnknown
	var at time.Time
	for _, e := range r.entries {
		if e.ID == id && !e.EffectiveDate.After(t) && (at.IsZero() || e.EffectiveDate.After(at)) {
			phase, at = e.Phase, e.EffectiveDate
		}
	}
	return phase, nil
}

func (r entriesRegistry) Entries(context.Context, string) ([]vc.LifecycleEntry, error) {
	return nil, nil
}

func phaseFromName(t *testing.T, id, name string) vc.LifecyclePhase {
	t.Helper()
	switch name {
	case "Active":
		return vc.PhaseActive
	case "Deprecated":
		return vc.PhaseDeprecated
	case "Sunset":
		return vc.PhaseSunset
	}
	t.Fatalf("%s: unknown lifecycle phase %q", id, name)
	return vc.PhaseUnknown
}

// Lifecycle vectors pin phase evaluation AT proof.created. The implementation
// stamps proof.created at signing time, so the driver time-shifts every
// registry effectiveDate by (now - vector.proof_created): the order relations
// between created and the transition instants — the only thing PhaseAt reads —
// are preserved exactly, and the whole path stays real (real signature, real
// resolver, real verifier).
func TestDplaaxConfidenceLifecycleVectors(t *testing.T) {
	for i := 4; i <= 6; i++ {
		v := loadDplaax(t, vecID("confidence", i))
		t.Run(v.ID, func(t *testing.T) {
			var input struct {
				Registry []struct {
					ID            string `json:"id"`
					Phase         string `json:"phase"`
					EffectiveDate string `json:"effectiveDate"`
				} `json:"registry"`
				Cryptosuite  string `json:"cryptosuite"`
				ProofCreated string `json:"proof_created"`
			}
			mustParse(t, v.Input, &input)
			proofCreated, err := time.Parse(time.RFC3339, input.ProofCreated)
			if err != nil {
				t.Fatalf("proof_created: %v", err)
			}
			delta := time.Since(proofCreated)
			reg := entriesRegistry{}
			for _, e := range input.Registry {
				ed, err := time.Parse(time.RFC3339, e.EffectiveDate)
				if err != nil {
					t.Fatalf("effectiveDate: %v", err)
				}
				reg.entries = append(reg.entries, registryEntry{
					ID:            e.ID,
					Phase:         phaseFromName(t, v.ID, e.Phase),
					EffectiveDate: ed.Add(delta),
				})
			}

			cred, pub := signedFixtureCred(t)
			if input.Cryptosuite != vc.CryptosuiteEdDSAJCS2022 {
				// The suite under test is unsignable by construction (only
				// eddsa-jcs-2022 is registered); carry it via wire mutation. The
				// verifier's lifecycle gate is evaluated before the signature, so
				// the vector's verdict still hinges on the registry state.
				cred = mutateWire(t, cred, func(m map[string]any) {
					m["proof"].(map[string]any)["cryptosuite"] = input.Cryptosuite
				})
			}
			verifier := vc.NewVerifier(fixtureResolver(t, pub), ed25519.Verifier{},
				vc.WithLifecycleRegistry(reg))
			res, err := verifier.Verify(context.Background(), cred)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if want := expectConfidence(t, v); res.Overall != want {
				t.Errorf("Overall = %v, want %v (axes %+v)", res.Overall, want, res.Axes)
			}
		})
	}
}

// --- delegation family ---
//
// delegation.Verify checks a REAL signature, so the driver rebuilds each
// vector's credential through delegation.Build with a fixture owner key
// (grafting the fields Build refuses to produce), and serves the issuer's
// document from a fixture resolver. Structural defects checked before the
// signature (purpose, scope, foreign subject) survive the re-signing.
func TestDplaaxDelegationVectors(t *testing.T) {
	for i := 1; i <= 5; i++ {
		v := loadDplaax(t, vecID("delegation", i))
		t.Run(v.ID, func(t *testing.T) {
			var input struct {
				Credential json.RawMessage `json:"credential"`
			}
			mustParse(t, v.Input, &input)
			var wire delegation.DelegationCredential
			if err := json.Unmarshal(input.Credential, &wire); err != nil {
				t.Fatalf("parse delegation credential: %v", err)
			}
			want := expectString(t, v)

			ks, signer := fixtureSigner(t, wire.Issuer)
			built, err := delegation.Build(signer, wire.Issuer, delegation.DelegationSubject{
				ID:          wire.CredentialSubject.ID,
				DelegatedBy: wire.CredentialSubject.DelegatedBy,
			})
			if err != nil {
				// Build refuses what Verify would refuse (e.g. delegatedBy != issuer);
				// a reject vector may legitimately end here.
				if want != "reject" {
					t.Errorf("Build rejected an accept vector: %v", err)
				}
				return
			}
			// Graft the vector's unsigned/structural deviations onto the signed
			// credential: scope is outside the signed body by design; the proof
			// fields under test are checked before the signature.
			built.CredentialSubject.Scope = wire.CredentialSubject.Scope
			if wire.Proof != nil && wire.Proof.ProofPurpose != built.Proof.ProofPurpose {
				built.Proof.ProofPurpose = wire.Proof.ProofPurpose
			}

			r := local.New()
			r.Add(ownerDoc(t, wire.Issuer, ks))
			err = delegation.Verify(context.Background(), ed25519.Verifier{}, r, built)
			if (err == nil) != (want == "accept") {
				t.Errorf("Verify err=%v, want %s", err, want)
			}
		})
	}
}

// --- signer family ---

func TestDplaaxSignerVectors(t *testing.T) {
	for i := 1; i <= 2; i++ {
		v := loadDplaax(t, vecID("signer", i))
		t.Run(v.ID, func(t *testing.T) {
			var input struct {
				Credential json.RawMessage `json:"credential"`
			}
			mustParse(t, v.Input, &input)
			cred := mustCred(t, input.Credential)
			proof := cred.Proof()
			if proof == nil {
				t.Fatal("vector credential carries no proof")
			}
			// The mandatory-member and no-op-identifier gates fire in
			// VerifyProof before any key material is consulted, so the fixture
			// proofValue never has to verify. Non-vacuity: the fixture proof
			// would ALSO fail later for incidental reasons (nil key, synthetic
			// proofValue), so the reject must be pinned to the cryptosuite
			// gate, not merely to any error.
			err := vc.VerifyProof(ed25519.Verifier{}, nil, proof, cred.Body())
			want := expectString(t, v)
			if (err == nil) != (want == "accept") {
				t.Errorf("VerifyProof err=%v, want %s", err, want)
			}
			if err != nil && !strings.Contains(err.Error(), "cryptosuite") {
				t.Errorf("rejected at the wrong gate (want the cryptosuite gate): %v", err)
			}
		})
	}

	v := loadDplaax(t, "signer-003")
	t.Run(v.ID, func(t *testing.T) {
		var input struct {
			RegistryOp struct {
				Op string `json:"op"`
				ID string `json:"id"`
			} `json:"registry_op"`
		}
		mustParse(t, v.Input, &input)
		if input.RegistryOp.Op != "register" {
			t.Fatalf("unhandled registry op %q", input.RegistryOp.Op)
		}
		rejected := func() (r bool) {
			defer func() { r = recover() != nil }()
			vc.RegisterCryptosuite(input.RegistryOp.ID, jcs.Canonicalizer{})
			return false
		}()
		if want := expectString(t, v); rejected != (want == "reject") {
			t.Errorf("RegisterCryptosuite(%q) rejected=%v, want %s", input.RegistryOp.ID, rejected, want)
		}
	})
}

// --- shared fixture helpers ---

func vecID(family string, n int) string {
	return fmt.Sprintf("%s-%03d", family, n)
}

func mustParse(t *testing.T, raw json.RawMessage, v any) {
	t.Helper()
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("parse: %v", err)
	}
}

func mustCred(t *testing.T, raw json.RawMessage) *vc.PipelinePassCredential {
	t.Helper()
	var c vc.PipelinePassCredential
	if err := c.UnmarshalJSON(raw); err != nil {
		t.Fatalf("unmarshal credential: %v", err)
	}
	return &c
}

const (
	fxOwner  = "did:dplaax:conf.example:org:acme"
	fxIssuer = fxOwner + ":pipeline:p1:process:s1"
)

// signedFixtureCred builds a real signed FirstDrop under fxIssuer and returns
// it with the issuer's public key.
func signedFixtureCred(t *testing.T) (*vc.PipelinePassCredential, []byte) {
	t.Helper()
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	ks := filestore.New(t.TempDir())
	if err := ks.SaveKeyPair(fxIssuer, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
		t.Fatalf("save key: %v", err)
	}
	cred, err := vc.NewBuilder(ed25519.NewSigner(ks)).BuildFirstDrop(
		fxIssuer, string(keystore.KeyIDSigning), fxIssuer+"#signing",
		vc.CredentialSubjectFields{
			PipelineID:          "p1",
			ProcessID:           "s1",
			TransformationClaim: vc.ClaimConvert,
			InputHash:           "sha256:" + strings.Repeat("ab", 32),
			OutputHash:          "sha256:" + strings.Repeat("cd", 32),
		}, nil)
	if err != nil {
		t.Fatalf("BuildFirstDrop: %v", err)
	}
	return cred, kp.PublicKey
}

// fixtureResolver serves fxIssuer's document (with the assertion key) and its
// self-controlled owner.
func fixtureResolver(t *testing.T, pub []byte) *local.Resolver {
	t.Helper()
	r := local.New()
	r.Add(fixtureDoc(fxIssuer, fxOwner, fxIssuer+"#signing", pub))
	r.Add(fixtureDoc(fxOwner, fxOwner, "", nil))
	return r
}

func fixtureDoc(id, controller, vmID string, pub []byte) *did.DIDDocument {
	fields := did.DocumentFields{ID: id, Controller: controller}
	if pub != nil {
		fields.VerificationMethod = []did.VerificationMethod{{
			ID:         vmID,
			Type:       "JsonWebKey2020",
			Controller: id,
			PublicKeyJWK: map[string]any{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(pub),
			},
		}}
		fields.AssertionMethod = []string{vmID}
	}
	return did.New(fields)
}

// mutateWire round-trips cred through its wire form applying mutate — the only
// way to hold a value no builder would sign.
func mutateWire(t *testing.T, cred *vc.PipelinePassCredential, mutate func(m map[string]any)) *vc.PipelinePassCredential {
	t.Helper()
	wire, err := cred.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(wire, &m); err != nil {
		t.Fatalf("unmarshal wire: %v", err)
	}
	mutate(m)
	reWire, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	var rt vc.PipelinePassCredential
	if err := rt.UnmarshalJSON(reWire); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	return &rt
}

// fixtureSigner provisions a signing key for issuerDID and returns the
// keystore (for the DID document) and the signer.
func fixtureSigner(t *testing.T, issuerDID string) (*crypto.KeyPair, crypto.Signer) {
	t.Helper()
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	ks := filestore.New(t.TempDir())
	if err := ks.SaveKeyPair(issuerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
		t.Fatalf("save key: %v", err)
	}
	return kp, ed25519.NewSigner(ks)
}

// ownerDoc builds the owner's self-controlled document carrying the signing
// assertion key delegation.Verify resolves.
func ownerDoc(t *testing.T, ownerDID string, kp *crypto.KeyPair) *did.DIDDocument {
	t.Helper()
	return fixtureDoc(ownerDID, ownerDID, ownerDID+"#"+string(keystore.KeyIDSigning), kp.PublicKey)
}
