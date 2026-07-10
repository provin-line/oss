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
	registerRunner(runProcess, "process", 5, 6)
	dplaaxRunners["process-004"] = runProcessSinkVerify

	// Blocked on missing implementation surface — ledgered so the coverage
	// guard keeps the gap visible rather than silently uncovered. These are
	// recorded in the gap-backlog, not driver TODOs. Each reason names its own
	// true blocker (not a blanket family reason).
	dplaaxSkips["resolver-006"] = "blocked-on: no eviction/delete API in vcresolver.Store — the forbidden Resolved->NotFound transition cannot be constructed"
	dplaaxSkips["resolver-007"] = "blocked-on: no batch-lookup RPC in dplaax.vc.v1 — batchresolver is an internal async worker, not a client endpoint"
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
