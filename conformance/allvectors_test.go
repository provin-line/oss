package conformance_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// vectorRunner drives one already-loaded vector against the implementation.
// The dispatcher (TestDplaaxAllVectors) owns loading, the subtest, and skips.
type vectorRunner func(t *testing.T, v dplaaxVector)

// dplaaxRunners maps a vector id to its driver; dplaaxSkips maps a vector id to
// a skip reason. Together they are the declarative coverage ledger: every
// vector in MANIFEST.sha256 MUST appear in exactly one of them, enforced by
// TestDplaaxAllVectors via checkCoverage. A vector synced in without a driver
// or a ledgered skip turns the harness red — silent partial coverage cannot
// survive.
var (
	dplaaxRunners = map[string]vectorRunner{}
	dplaaxSkips   = map[string]string{}
)

func registerRunner(runner vectorRunner, family string, lo, hi int) {
	for i := lo; i <= hi; i++ {
		dplaaxRunners[vecID(family, i)] = runner
	}
}

func registerSkip(family string, lo, hi int, reason string) {
	for i := lo; i <= hi; i++ {
		dplaaxSkips[vecID(family, i)] = reason
	}
}

func init() {
	// Tranche 1 — pure-function families (drivers in dplaax_test.go).
	registerRunner(runCanon, "canon", 1, 8)
	registerRunner(runCred, "cred", 1, 32)
	registerRunner(runCommitment, "commitment", 1, 11)
	dplaaxRunners["commitment-013"] = runCommitment
	registerRunner(runChainContinuity, "chain", 6, 8)
	registerRunner(runConfidenceSynthesis, "confidence", 1, 3)
	registerRunner(runConfidenceLifecycle, "confidence", 4, 6)
	registerRunner(runDelegation, "delegation", 1, 5)
	registerRunner(runSignerProof, "signer", 1, 2)
	dplaaxRunners["signer-003"] = runSignerRegister
	dplaaxRunners["identity-001"] = runIdentityDerivation
	dplaaxRunners["identity-002"] = runIdentityReissue

	// Tranche 2 — behavior-fixture families driven against real seams
	// (tranche2_test.go).
	dplaaxRunners["commitment-012"] = runCommitmentPersistence
	registerRunner(runChainTrigger, "chain", 1, 5)
	registerRunner(runAuditAttribution, "audit", 1, 4)
	registerRunner(runRegistry, "registry", 1, 2)
	registerRunner(runResolverAddress, "resolver", 1, 2)
	dplaaxRunners["resolver-003"] = runResolverImmutability
	registerRunner(runResolverStates, "resolver", 4, 5)
	dplaaxRunners["resolver-008"] = runResolverBodyEncoding
	dplaaxRunners["resolver-009"] = runResolverStates // non-authoritative NotFound (P0-11)
	registerRunner(runProcess, "process", 5, 6)
	dplaaxRunners["process-004"] = runProcessSinkVerify

	// identity family, store half: write-once/append-only admission and the
	// legacy body-only projection, driven against the real variant store.
	registerRunner(runIdentityStore, "identity", 3, 7)

	// transfer family: audit-reachable transfer evidence records (emission,
	// ingress, relationship) — the federation-layer domain settled 2026-07-11.
	// Each vector has a distinct expect shape, so each is its own driver.
	dplaaxRunners["transfer-001"] = runTransferEvidenceDefinition
	dplaaxRunners["transfer-002"] = runTransferEmissionAppendOnly
	dplaaxRunners["transfer-003"] = runTransferIngressRetention
	dplaaxRunners["transfer-004"] = runTransferRelationshipRecord

	// did-resolution family: auth.resolve.* driven against the real outbound
	// resolver, network/pkg/didresolver (drivers in didresolution_test.go).
	dplaaxRunners["did-resolution-id-mismatch-001"] = runDidResolutionHTTP
	dplaaxRunners["did-resolution-unavailable-001"] = runDidResolutionHTTP

	// Not runnable by design — ledgered so the coverage guard keeps the
	// reasoning visible rather than silently uncovered. Each reason names its
	// own ground (not a blanket family reason).
	//
	// resolver-006 is STRUCTURALLY ENFORCED, not blocked (P0-11 ruling):
	// nothing in the store can remove a credential — VariantStore offers
	// PutVariant/Get/GetVariant/ListVariantIDs/ListHashes, and VariantBackend
	// underneath it has no delete either — so the forbidden Resolved->NotFound
	// transition is unconstructible; the API's absence is the strongest
	// enforcement. The variant set is append-only, which makes the property
	// stronger than it was: a body's evidence can now only grow. (Pool.Remove is
	// the unresolved-holes queue, not the credential store.) The vector is
	// retained as the shape pin should an eviction surface ever appear — at
	// which point this entry converts to a driver.
	dplaaxSkips["resolver-006"] = "structurally enforced: neither vcresolver.VariantStore nor VariantBackend has an eviction/delete surface, so the forbidden Resolved->NotFound transition is unconstructible (P0-11; vector retained as the shape pin for any future eviction surface)"
	// resolver-007 is RESERVED, not blocked (P0-11 ruling): resolver.batch.shape
	// binds any batch lookup surface an implementation or profile adds, without
	// obligating one to exist; dplaax.vc.v1 defines none (batchresolver is an
	// internal async worker, not a lookup surface).
	dplaaxSkips["resolver-007"] = "reserved: resolver.batch.shape binds a future batch lookup surface; none exists in dplaax.vc.v1 (P0-11; the vector pins the shape such a surface must satisfy)"
	// auth-grant-kid-mismatch-001 binds the L1 DID-grant JWS path (the
	// /oauth/token grant's three-way kid match: header kid / payload method id
	// / resolver-selected method id). This repo has no JWS grant surface —
	// wireauth is detached Ed25519 proofs, not JWS — so there is nothing here
	// for the vector to drive. provin-line/auth vendors the vector byte-exact
	// and runs it in its conformance harness (integration/conformance); this
	// entry converts to a driver if a JWS grant surface ever lands here.
	dplaaxSkips["auth-grant-kid-mismatch-001"] = "subject is the L1 DID-grant JWS path (three-way kid match at /oauth/token) — no JWS grant surface in this repo; provin-line/auth vendors and drives this vector in its conformance harness"
	registerSkip("process", 1, 3, "blocked-on: no process-type/behavior classifier seam — the four-type catalog (process.catalog/chained.stateless/source.firstdrop) is a static deployment attribute, not a callable classifier")

	// Vectors of rules whose SUBJECT does not exist in this implementation
	// yet. They arrived here because vendoring is whole-corpus by design
	// (scripts/sync-spec-vectors.sh mirrors the catalog; there is no partial
	// adoption), so the catalog had outrun the harness silently — these
	// entries are what makes that visible. Each converts to a driver in the
	// slice that builds its subject; none is a judgment that the rule is
	// unimportant.
	registerSkip("claims-coverage", 1, 4, "blocked-on: no EvaluationViewManifest/EvidenceViewID type — the scoped evidence vector these pin is the artifact P0-1 slice B builds (inv 4-9); nothing here can carry a per-scope coverage/truth-state today")
	registerSkip("claims-effect", 1, 2, "blocked-on: no effect-scope mapping or legacy receipt projection — both are surfaces of the P0-5 external-effect gate, unimplemented (spec transcribed 2026-07-15, catalog rules effect.*)")
	registerSkip("claims-policy", 1, 1, "blocked-on: no policy-decision surface — claims.policy.no-accept-non-verified binds a decision profile consuming an evidence view; neither type exists until P0-1 slice B and the P0-5 effect gate land")
	registerSkip("effect", 1, 13, "blocked-on: no external-effect gate — the P0-5 subject (ReleaseAuthorization, quarantine entries, ObservationRecord/DecisionRecord, the effect state machine) is spec-only; the catalog transcription landed 2026-07-15 ahead of any implementation")
	registerSkip("release", 1, 13, "blocked-on: no release-engineering pipeline in this repo — the P0-7 subject (evidence manifests, advisory assessments, waivers, scan/build state machines) is CI/release infrastructure, not library code; these bind that pipeline when it is built")
}

// TestDplaaxAllVectors is the single CI-facing entry point. It first proves the
// coverage ledger is complete against MANIFEST.sha256 (no unrun vector, no
// double-listed vector, no ledger entry outside the manifest), then executes
// every vector as a subtest — running its driver or skipping with its reason.
// The completeness check reads only the static maps and the manifest, so it is
// unaffected by -run filtering or subtest execution order.
func TestDplaaxAllVectors(t *testing.T) {
	manifest := manifestIDs(t)
	if problems := checkCoverage(manifest, keysOf(dplaaxRunners), keysOf(dplaaxSkips)); len(problems) > 0 {
		for _, p := range problems {
			t.Error(p)
		}
		return // a broken ledger: do not run subtests against it
	}
	for _, id := range manifest {
		id := id
		t.Run(id, func(t *testing.T) {
			if reason, skipped := dplaaxSkips[id]; skipped {
				t.Skip(reason)
			}
			dplaaxRunners[id](t, loadDplaax(t, id))
		})
	}
}

// manifestIDs returns the vector ids listed in MANIFEST.sha256, sorted. It is
// the authoritative set the coverage ledger must cover exactly.
func manifestIDs(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dplaaxVectorDir, "MANIFEST.sha256"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var ids []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("malformed manifest line %q", line)
		}
		name := strings.TrimPrefix(fields[1], "*")
		ids = append(ids, strings.TrimSuffix(name, ".json"))
	}
	sort.Strings(ids)
	return ids
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
