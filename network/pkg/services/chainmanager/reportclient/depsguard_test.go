package reportclient_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestProdDeps_NoChainManagerRootInReportClient guards the architectural
// promise this fix sets up (PR3b Task 8, applying the T2 split
// auditor/payloadresolver/tlogservice already had): chainmanager/reportclient
// depends on the chainmanager/wirecontract LEAF for its shared op name and
// signed-view field builder, never the chainmanager SERVICE ROOT (which
// carries the Service implementation and its store/infra/emithealth
// dependencies) — so cmd/pipeline can import this client without dragging
// server-side domain logic in transitively (mirrors auditor/client's own
// guard, auditor/client/depsguard_test.go).
func TestProdDeps_NoChainManagerRootInReportClient(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps",
		"github.com/provin-line/oss/network/pkg/services/chainmanager/reportclient",
	).CombinedOutput()
	if err != nil {
		t.Skipf("go list unavailable: %v\n%s", err, out)
	}
	const root = "github.com/provin-line/oss/network/pkg/services/chainmanager"
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == root {
			t.Errorf("chainmanager/reportclient production deps include the service root %q — it must depend only on chainmanager/wirecontract", root)
		}
	}
}
