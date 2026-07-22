package client_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestProdDeps_NoTlogserviceRootInClient guards the architectural promise
// PR3b Task 2 sets up: tlogservice/client depends on the
// tlogservice/wirecontract LEAF for its shared op name, signed-view
// builders, and record_payloads_framed codec, never the tlogservice SERVICE
// ROOT (which carries mirrorstore, logident, and the rest of the
// server-side domain) — so a future cmd/pipeline binary can import this
// client without dragging server logic in transitively (mirrors
// cmd/network's own production-import-graph guard,
// cmd/network/depsguard_test.go).
func TestProdDeps_NoTlogserviceRootInClient(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps",
		"github.com/provin-line/oss/network/pkg/services/tlogservice/client",
	).CombinedOutput()
	if err != nil {
		t.Skipf("go list unavailable: %v\n%s", err, out)
	}
	const root = "github.com/provin-line/oss/network/pkg/services/tlogservice"
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == root {
			t.Errorf("tlogservice/client production deps include the service root %q — it must depend only on tlogservice/wirecontract", root)
		}
	}
}
