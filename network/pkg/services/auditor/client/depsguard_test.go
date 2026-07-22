package client_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestProdDeps_NoAuditorRootInClient guards the architectural promise PR3b
// Task 2 sets up: auditor/client depends on the auditor/wirecontract LEAF for
// its shared op names, signed-view builders, and consumed-set
// canonicalization, never the auditor SERVICE ROOT (which carries the
// receipt/status stores, the audit runner, and the rest of the server-side
// domain) — so a future cmd/pipeline binary can import this client without
// dragging server logic in transitively (mirrors cmd/network's own
// production-import-graph guard, cmd/network/depsguard_test.go).
func TestProdDeps_NoAuditorRootInClient(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps",
		"github.com/provin-line/oss/network/pkg/services/auditor/client",
	).CombinedOutput()
	if err != nil {
		t.Skipf("go list unavailable: %v\n%s", err, out)
	}
	const root = "github.com/provin-line/oss/network/pkg/services/auditor"
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == root {
			t.Errorf("auditor/client production deps include the service root %q — it must depend only on auditor/wirecontract", root)
		}
	}
}
