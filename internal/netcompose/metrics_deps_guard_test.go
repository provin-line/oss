package netcompose

import (
	"os/exec"
	"strings"
	"testing"
)

// TestProdDeps_MetricsStayAtCompositionRoot: the P1-2 dependency rule — the
// library layers expose stdlib poll accessors and NEVER import OpenTelemetry
// or Prometheus; only the composition root (internal/netcompose's metrics
// bridge, this package, and the cmd/ binaries that wire it) may. Guarded on
// the production graphs of the pipeline, vc/tlog, and network service layers.
//
// pipeline/runtime is a DOCUMENTED, temporary exception (PR3a Task 2 — the
// cmd/standalone data-plane mechanical move): it carries a mid-branch import
// of internal/netcompose for the LoopMetrics/schemaGetter aliases and the
// bearer/schema-ref-at-boot helpers dataplane.go called under cmd/standalone
// before the move, which pulls this package's own OTel/Prometheus deps in
// transitively. The boundary-surgery follow-up (Task 3) severs that import
// and closes this exception — this guard must go back to covering all of
// pipeline/... once it does.
func TestProdDeps_MetricsStayAtCompositionRoot(t *testing.T) {
	pkgsOut, err := exec.Command("go", "list",
		"github.com/provin-line/oss/pipeline/...",
		"github.com/provin-line/oss/network/...",
		"github.com/provin-line/oss/vc/...",
		"github.com/provin-line/oss/tlog/...",
	).CombinedOutput()
	if err != nil {
		t.Skipf("go list unavailable: %v\n%s", err, pkgsOut)
	}
	const exception = "github.com/provin-line/oss/pipeline/runtime"
	var pkgs []string
	for _, line := range strings.Split(string(pkgsOut), "\n") {
		p := strings.TrimSpace(line)
		if p == "" || p == exception {
			continue
		}
		pkgs = append(pkgs, p)
	}
	out, err := exec.Command("go", append([]string{"list", "-deps"}, pkgs...)...).CombinedOutput()
	if err != nil {
		t.Skipf("go list unavailable: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		dep := strings.TrimSpace(line)
		if strings.HasPrefix(dep, "go.opentelemetry.io/") || strings.HasPrefix(dep, "github.com/prometheus/") {
			t.Errorf("library production deps include %q — metrics vendor leaked below the composition root", dep)
		}
	}
}
