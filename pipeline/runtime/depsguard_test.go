package runtime

import (
	"os/exec"
	"strings"
	"testing"
)

// The architectural promise of this tree: pipeline/ never imports network/
// or the cmd/ deployment roots (AGENTS.md rule 2 — network/ and pipeline/
// interact over the wire, never in-process). Guarded on the production
// import graph for the whole pipeline/ tree, not just this package (mirrors
// cmd/network's depsguard, which pins the same rule from the other side).
func TestProdDeps_NoNetworkOrCmdInPipelineTree(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps",
		"github.com/provin-line/oss/pipeline/...",
	).CombinedOutput()
	if err != nil {
		t.Skipf("go list unavailable: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		dep := strings.TrimSpace(line)
		if strings.HasPrefix(dep, "github.com/provin-line/oss/network/") ||
			dep == "github.com/provin-line/oss/internal/netcompose" ||
			strings.HasPrefix(dep, "github.com/provin-line/oss/cmd/") {
			t.Errorf("pipeline/... production deps include %q — network/ and pipeline/ must interact only over the wire (AGENTS.md rule 2)", dep)
		}
	}
}
