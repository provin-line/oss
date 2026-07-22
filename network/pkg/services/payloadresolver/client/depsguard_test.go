package client_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestProdDeps_NoPayloadresolverRootInClient guards the architectural
// promise PR3b Task 2 sets up: payloadresolver/client depends on the
// payloadresolver/wirecontract LEAF for its shared op name and signed-view
// builder, never the payloadresolver SERVICE ROOT (which carries the
// store/handler domain logic) — so a future cmd/pipeline binary can import
// this client without dragging server logic in transitively (mirrors
// cmd/network's own production-import-graph guard,
// cmd/network/depsguard_test.go).
func TestProdDeps_NoPayloadresolverRootInClient(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps",
		"github.com/provin-line/oss/network/pkg/services/payloadresolver/client",
	).CombinedOutput()
	if err != nil {
		t.Skipf("go list unavailable: %v\n%s", err, out)
	}
	const root = "github.com/provin-line/oss/network/pkg/services/payloadresolver"
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == root {
			t.Errorf("payloadresolver/client production deps include the service root %q — it must depend only on payloadresolver/wirecontract", root)
		}
	}
}
