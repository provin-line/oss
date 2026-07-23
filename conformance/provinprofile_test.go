// The provin PROFILE conformance harness: the vectors of
// provin-line/profile.spec, vendored byte-exact under vectors/provin/ and run
// against this implementation.
//
// It is separate from the dplaax harness on purpose. dPLaaX owns the wire; the
// profile owns what a claim ASSERTS. One harness over both would let a profile
// norm read as a protocol one, which is the confusion the two repositories were
// split to end.
//
// WHAT THIS HARNESS CAN AND CANNOT DRIVE, and why the skip ledger below is
// long. This library deliberately does not know what a claim means: its check
// is "structural, requiring no profile knowledge" (vc.ValidateTransformationClaim),
// and dplaax's open-world default is what makes that safe. So the profile's
// norms divide in two:
//
//   - GRAMMAR AND GROUNDING — is this token this profile's claim at all — is a
//     check the library makes, and these vectors drive it.
//   - CLOSURE — what the issuer warranted about where the output's information
//     came from, and what a consumer may therefore infer — is not a computation
//     anything here performs. It binds the issuer at signing time and the
//     consumer at reading time. The vectors pin it for them (and for a second
//     implementation that builds an inference surface); this harness records
//     that it has nothing to run them against.
//
// A skip here is a fact about where a norm binds, not a gap in coverage.
// (claim-003 was ledgered as a real gap when this harness landed; the
// issuance-side registry check closed it — ruled 2026-07-16.)
package conformance_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/vc"
)

const provinVectorDir = "vectors/provin"

var (
	provinRunners = map[string]vectorRunner{}
	provinSkips   = map[string]string{}
)

func registerProvinSkip(lo, hi int, reason string) {
	for i := lo; i <= hi; i++ {
		provinSkips[vecID("claim", i)] = reason
	}
}

func init() {
	// Grammar and grounding: the library's half.
	provinRunners["claim-001"] = runProfileGrounding
	provinRunners["claim-002"] = runProfileGrounding
	provinRunners["claim-003"] = runProfileRegistryClosed
	provinRunners["claim-013"] = runProfileTopologyIndependence

	// Closure is a warranty, not a computation: no surface here decides it,
	// and by design none should — the library's claim check is structural so
	// that an unrecognized claim stays open-world instead of being guessed at.
	registerProvinSkip(4, 10, "not a library check by design: closure is what the ISSUER warranted and what a CONSUMER may infer; this implementation's claim check is structural and profile-knowledge-free, so there is no closure verdict to drive (the vectors bind issuers, consumers, and any implementation that builds an inference surface)")

	// The sink receipt's identity shape is established by the issuer — the
	// unexported sinkReceiptRegistrar in pipeline/runtime (and the
	// provenance/vcdid signer it wraps), neither reachable from this
	// external test package. Their own tests pin the shape; this harness
	// cannot reach it without inverting the dependency.
	registerProvinSkip(11, 12, "issuer obligation outside this package: the identity shape is established by pipeline/runtime's unexported sinkReceiptRegistrar and its provenance/vcdid signer (unreachable from this external test package) and pinned by their own tests; vc grammar-validates and stays open-world, exactly as the rule says")
}

// TestProvinProfileAllVectors is the profile harness's single entry point. It
// proves the coverage ledger is complete against MANIFEST.sha256 before running
// anything, so a vector synced in without a driver or a ledgered reason turns
// this red rather than passing unnoticed.
func TestProvinProfileAllVectors(t *testing.T) {
	manifest := provinManifestIDs(t)
	if problems := checkCoverage(manifest, keysOf(provinRunners), keysOf(provinSkips)); len(problems) > 0 {
		for _, p := range problems {
			t.Error(p)
		}
		return
	}
	for _, id := range manifest {
		id := id
		t.Run(id, func(t *testing.T) {
			if reason, skipped := provinSkips[id]; skipped {
				t.Skip(reason)
			}
			provinRunners[id](t, loadProvin(t, id))
		})
	}
}

// TestProvinProfileVendoredManifest pins the vendored copies byte-exact: an
// in-place edit of a vendored vector is a drift bug, never a fix. Re-sync
// deliberately with scripts/sync-profile-vectors.sh.
func TestProvinProfileVendoredManifest(t *testing.T) {
	for _, id := range provinManifestIDs(t) {
		if _, err := os.Stat(filepath.Join(provinVectorDir, id+".json")); err != nil {
			t.Errorf("manifest lists %s but it is unreadable: %v", id, err)
		}
	}
	des, err := os.ReadDir(provinVectorDir)
	if err != nil {
		t.Fatal(err)
	}
	listed := toSet(provinManifestIDs(t))
	for _, de := range des {
		name := de.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		if id := strings.TrimSuffix(name, ".json"); !listed[id] {
			t.Errorf("%s is present but unlisted in MANIFEST.sha256 (re-sync rather than adding files by hand)", name)
		}
	}
}

func provinManifestIDs(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(provinVectorDir, "MANIFEST.sha256"))
	if err != nil {
		t.Fatalf("read profile manifest: %v", err)
	}
	var ids []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("malformed manifest line %q", line)
		}
		ids = append(ids, strings.TrimSuffix(strings.TrimPrefix(fields[1], "*"), ".json"))
	}
	sort.Strings(ids)
	return ids
}

func loadProvin(t *testing.T, id string) dplaaxVector {
	t.Helper()
	var v dplaaxVector
	loadVector(t, filepath.Join(provinVectorDir, id+".json"), &v)
	if v.ID != id {
		t.Fatalf("vector id %q != file %q", v.ID, id)
	}
	return v
}

// --- grammar and grounding (claim-001, 002) ---
//
// Drives the real receive-side check. The claim's identity is the (grounding
// URL, label) pair, not the bare prefix: a provin: token whose @context grounds
// nothing is a different assertion wearing the same spelling, and the grounding
// rides the signing scope, so the two are byte-distinguishable.
func runProfileGrounding(t *testing.T, v dplaaxVector) {
	var input struct {
		Credential json.RawMessage `json:"credential"`
	}
	mustParse(t, v.Input, &input)
	cred := mustCred(t, input.Credential)

	err := cred.ValidateTransformationClaim()
	want := expectString(t, v)
	if (err == nil) != (want == "accept") {
		t.Fatalf("ValidateTransformationClaim err=%v, want %s", err, want)
	}
	// Non-vacuity: a reject here must be about grounding, not an incidental
	// grammar or charset failure — the fixture's label is well-formed.
	if err != nil && !strings.Contains(err.Error(), "grounding") && !strings.Contains(err.Error(), "ground") {
		t.Errorf("rejected at the wrong gate (want the grounding gate): %v", err)
	}
}

// --- topology independence (claim-013) ---
//
// One claim, both topologies. A claim asserts an information source, not a
// chain shape, so neither presence nor absence of previousCredential follows
// from it — and the wire form must accept both without consulting the claim.
func runProfileTopologyIndependence(t *testing.T, v dplaaxVector) {
	var input struct {
		Sequence []struct {
			Op         string          `json:"op"`
			Credential json.RawMessage `json:"credential"`
		} `json:"sequence"`
	}
	mustParse(t, v.Input, &input)
	if len(input.Sequence) < 2 {
		t.Fatalf("vector carries %d credentials, want both topologies", len(input.Sequence))
	}

	claims := map[string]bool{}
	withPrev, withoutPrev := 0, 0
	for i, step := range input.Sequence {
		cred := mustCred(t, step.Credential)
		subject, err := cred.Subject()
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		if err := cred.ValidateTransformationClaim(); err != nil {
			t.Fatalf("step %d: the claim was rejected: %v", i, err)
		}
		if err := cred.ValidateWireForm(); err != nil {
			t.Fatalf("step %d: a %s under this topology was rejected: %v", i, subject.TransformationClaim, err)
		}
		claims[string(subject.TransformationClaim)] = true
		if cred.PreviousCredential() == "" {
			withoutPrev++
		} else {
			withPrev++
		}
	}
	if len(claims) != 1 {
		t.Fatalf("the vector uses %d claims, want ONE across both topologies", len(claims))
	}
	if withPrev == 0 || withoutPrev == 0 {
		t.Fatalf("the vector covers %d linked and %d origin credentials, want both", withPrev, withoutPrev)
	}
	if want := expectString(t, v); want != "accept" {
		t.Fatalf("unhandled expect %q", want)
	}
}

// --- the registry, closed where it binds: issuance (claim-003) ---
//
// The rule's two directions are deliberately asymmetric, and this driver pins
// both. EMITTING the fixture's unregistered label must fail — that is the
// registry being closed for issuance. RECEIVING the very same credential must
// still pass the claim check — that is the open-world rule, and it is what
// makes adding a label a minor change instead of a fleet upgrade. A regression
// in either direction is a different bug, so both are asserted against the
// same fixture.
func runProfileRegistryClosed(t *testing.T, v dplaaxVector) {
	var input struct {
		Credential json.RawMessage `json:"credential"`
	}
	mustParse(t, v.Input, &input)
	cred := mustCred(t, input.Credential)
	subject, err := cred.Subject()
	if err != nil {
		t.Fatal(err)
	}

	_, err = vc.New(vc.CredentialFields{
		Issuer:    cred.Issuer(),
		ValidFrom: time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC),
		Subject: vc.CredentialSubjectFields{
			PipelineID:          subject.PipelineID,
			ProcessID:           subject.ProcessID,
			TransformationClaim: subject.TransformationClaim,
			OutputHash:          subject.OutputHash,
		},
	})
	if want := expectString(t, v); (err == nil) != (want == "accept") {
		t.Fatalf("issuing %q: err=%v, want %s", subject.TransformationClaim, err, want)
	}
	if err != nil && !strings.Contains(err.Error(), "regist") {
		t.Errorf("rejected at the wrong gate (want the registry gate): %v", err)
	}

	// The same bytes, on the receive side: open-world, accepted.
	if err := cred.ValidateTransformationClaim(); err != nil {
		t.Errorf("the receive path rejected what issuance refused to emit — open-world is broken: %v", err)
	}
}
