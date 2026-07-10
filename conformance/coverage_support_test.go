package conformance_test

import "sort"

// checkCoverage reports every vector that is not covered exactly once and every
// registered id absent from the manifest. An empty result means: each manifest
// vector has exactly one of a runner or a skip, and no runner/skip references a
// vector outside the manifest. It is a pure function over the three id sets, so
// the completeness guard depends on no global state or test execution order.
func checkCoverage(manifest, runners, skips []string) []string {
	runnerSet := toSet(runners)
	skipSet := toSet(skips)
	manifestSet := toSet(manifest)

	var problems []string
	for _, id := range manifest {
		hasRunner := runnerSet[id]
		hasSkip := skipSet[id]
		switch {
		case hasRunner && hasSkip:
			problems = append(problems, id+": in BOTH the runner registry and the skip ledger (choose one)")
		case !hasRunner && !hasSkip:
			problems = append(problems, id+": no runner and no skip reason (write a driver or ledger a skip)")
		}
	}
	for _, id := range runners {
		if !manifestSet[id] {
			problems = append(problems, id+": runner registered but the vector is not in MANIFEST.sha256")
		}
	}
	for _, id := range skips {
		if !manifestSet[id] {
			problems = append(problems, id+": skip ledgered but the vector is not in MANIFEST.sha256")
		}
	}
	sort.Strings(problems)
	return problems
}

func toSet(ids []string) map[string]bool {
	s := make(map[string]bool, len(ids))
	for _, id := range ids {
		s[id] = true
	}
	return s
}
