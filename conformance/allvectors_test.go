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

	// transfer family: audit-reachable transfer evidence records (emission,
	// ingress, relationship) — the federation-layer domain settled 2026-07-11.
	// Each vector has a distinct expect shape, so each is its own driver.
	dplaaxRunners["transfer-001"] = runTransferEvidenceDefinition
	dplaaxRunners["transfer-002"] = runTransferEmissionAppendOnly
	dplaaxRunners["transfer-003"] = runTransferIngressRetention
	dplaaxRunners["transfer-004"] = runTransferRelationshipRecord

	// Not runnable by design — ledgered so the coverage guard keeps the
	// reasoning visible rather than silently uncovered. Each reason names its
	// own ground (not a blanket family reason).
	//
	// resolver-006 is STRUCTURALLY ENFORCED, not blocked (P0-11 ruling):
	// vcresolver.Store exposes no eviction/delete surface (Put/Get/ListHashes —
	// store.go), so the forbidden Resolved->NotFound transition is
	// unconstructible; the API's absence is the strongest enforcement.
	// (Pool.Remove is the unresolved-holes queue, not the credential store.)
	// The vector is retained as the shape pin should an eviction surface ever
	// appear — at which point this entry converts to a driver.
	dplaaxSkips["resolver-006"] = "structurally enforced: vcresolver.Store has no eviction/delete surface, so the forbidden Resolved->NotFound transition is unconstructible (P0-11; vector retained as the shape pin for any future eviction surface)"
	// resolver-007 is RESERVED, not blocked (P0-11 ruling): resolver.batch.shape
	// binds any batch lookup surface an implementation or profile adds, without
	// obligating one to exist; dplaax.vc.v1 defines none (batchresolver is an
	// internal async worker, not a lookup surface).
	dplaaxSkips["resolver-007"] = "reserved: resolver.batch.shape binds a future batch lookup surface; none exists in dplaax.vc.v1 (P0-11; the vector pins the shape such a surface must satisfy)"
	registerSkip("process", 1, 3, "blocked-on: no process-type/behavior classifier seam — the four-type catalog (process.catalog/chained.stateless/source.firstdrop) is a static deployment attribute, not a callable classifier")
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
