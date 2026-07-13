package livepublisher_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestProdDeps_ExcludeBrokerServer: the livepublisher may import the nats.go
// CLIENT (that is its job) but must never pull the nats-server into the
// production graph.
func TestProdDeps_ExcludeBrokerServer(t *testing.T) {
	const pkg = "github.com/provin-line/oss/network/pkg/services/chainmanager/infra/nats/livepublisher"
	out, err := exec.Command("go", "list", "-deps", pkg).CombinedOutput()
	if err != nil {
		t.Skipf("go list unavailable: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		dep := strings.TrimSpace(line)
		if dep == "github.com/nats-io/nats-server" || strings.HasPrefix(dep, "github.com/nats-io/nats-server/") {
			t.Errorf("production deps include %q — broker server pulled into the prod graph", dep)
		}
	}
}
