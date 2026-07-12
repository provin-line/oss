package aggregate

import (
	"testing"
	"time"

	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	"github.com/provin-line/oss/tlog/memlog"
)

// An aggregate is a by-reference producer, so it exposes the stripped-publish
// health signal the control-plane gate consumes. A fresh process delegates to
// its (non-nil, construction-time) emitter's optimistic default (healthy).
func TestProcess_StrippedPublishHealthAccessors(t *testing.T) {
	cfg := Config{
		Ingress: []Ingress{{Subscriber: &captureSubscriber{}}}, Window: time.Hour,
		Signer: &recordSigner{}, Verifier: stubVerifier{}, Store: &recordStore{},
		Publisher: &recordPublisher{}, Codec: envelopecodec.New(), Emission: memlog.New(),
		Fold: ManifestFold{},
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !p.StrippedPublishHealthy() {
		t.Error("fresh process: want healthy (no failed stripped publish yet)")
	}
	if n := p.StrippedPublishFailures(); n != 0 {
		t.Errorf("fresh process: count = %d, want 0", n)
	}
}
