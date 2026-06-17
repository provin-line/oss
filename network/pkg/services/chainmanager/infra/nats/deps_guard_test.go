package nats_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestProdDeps_ExcludeBrokerServer is the automated guard for D-n7: the
// production import graph of infra/nats must NOT contain the nats-server or the
// nats.go client — those are test-only (the embedded isolation e2e). `go list
// -deps` lists a package's NON-test dependencies, so any appearance here means a
// non-_test.go file pulled the broker into the production binary's transitive
// graph (an AGENTS.md rule-1 / Hub swap-point violation). The operator needs only
// jwt + nkeys to build and sign account claims.
func TestProdDeps_ExcludeBrokerServer(t *testing.T) {
	const pkg = "github.com/provin-line/oss/network/pkg/services/chainmanager/infra/nats"
	out, err := exec.Command("go", "list", "-deps", pkg).CombinedOutput()
	if err != nil {
		t.Skipf("go list unavailable: %v\n%s", err, out)
	}
	forbidden := []string{
		"github.com/nats-io/nats-server",
		"github.com/nats-io/nats.go",
	}
	for _, line := range strings.Split(string(out), "\n") {
		dep := strings.TrimSpace(line)
		for _, f := range forbidden {
			if dep == f || strings.HasPrefix(dep, f+"/") {
				t.Errorf("production deps of infra/nats include %q — broker pulled into the prod graph (D-n7)", dep)
			}
		}
	}
}
