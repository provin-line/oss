package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The architectural promise of this binary: the network node carries NO
// data-plane code. Guarded on the production import graph (mirrors
// netcompose's metrics deps guard).
func TestProdDeps_NoPipelineInNetworkBinary(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps",
		"github.com/provin-line/oss/cmd/network",
	).CombinedOutput()
	if err != nil {
		t.Skipf("go list unavailable: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		dep := strings.TrimSpace(line)
		if strings.HasPrefix(dep, "github.com/provin-line/oss/pipeline") {
			t.Errorf("cmd/network production deps include %q — the network binary must not contain data-plane code", dep)
		}
	}
}
