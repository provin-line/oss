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
func TestProdDeps_MetricsStayAtCompositionRoot(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps",
		"github.com/provin-line/oss/pipeline/...",
		"github.com/provin-line/oss/network/...",
		"github.com/provin-line/oss/vc/...",
		"github.com/provin-line/oss/tlog/...",
	).CombinedOutput()
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
