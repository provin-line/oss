package nats_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestProdDeps_ExcludeBrokerServer is the automated guard for D-17a-6. Unlike the
// control-plane chainmanager/infra/nats package (which forbids BOTH the client and
// the server), this data-plane transport legitimately imports the nats.go CLIENT in
// production — that is the intended introduction of nats.go into the prod graph. What
// must stay out is the embedded nats-server, a test-only harness. `go list -deps`
// lists a package's NON-test dependencies, so any appearance of the server here means
// a non-_test.go file pulled the embedded broker into the production binary's graph.
func TestProdDeps_ExcludeBrokerServer(t *testing.T) {
	const pkg = "github.com/provin-line/oss/pipeline/transport/nats"
	out, err := exec.Command("go", "list", "-deps", pkg).CombinedOutput()
	if err != nil {
		t.Skipf("go list unavailable: %v\n%s", err, out)
	}
	const forbidden = "github.com/nats-io/nats-server"
	for _, line := range strings.Split(string(out), "\n") {
		dep := strings.TrimSpace(line)
		if dep == forbidden || strings.HasPrefix(dep, forbidden+"/") {
			t.Errorf("production deps of pipeline/transport/nats include %q — embedded broker pulled into the prod graph (D-17a-6)", dep)
		}
	}
}
