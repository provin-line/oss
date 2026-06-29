package auditor_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/vc"
)

func TestMemStatusStore_RoundTrip(t *testing.T) {
	s := auditor.NewMemStatusStore()

	if _, ok := s.Get("absent"); ok {
		t.Errorf("absent head: got ok=true, want false")
	}

	rec := auditor.AuditRecord{
		Overall: vc.ConfidenceVerified,
		Axes: vc.AxisResult{
			DataIntegrity:      vc.ConfidenceVerified,
			SignerAuthenticity: vc.ConfidenceVerified,
			ChainConsistency:   vc.ConfidenceVerified,
		},
		Notations: []string{"deprecated-cryptosuite"},
		Scope:     auditor.AuditScope{LinearChain: true, SourceCommitmentEvaluated: false},
		AuditedAt: time.Unix(1700000000, 0).UTC(),
	}
	if err := s.Put("sha256:h", rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok := s.Get("sha256:h")
	if !ok {
		t.Fatal("present head: got ok=false, want true")
	}
	if !reflect.DeepEqual(got, rec) {
		t.Errorf("round-trip mismatch:\n got = %+v\nwant = %+v", got, rec)
	}

	// Latest audit wins (overwrite).
	rec2 := rec
	rec2.Overall = vc.ConfidenceFailed
	if err := s.Put("sha256:h", rec2); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Get("sha256:h"); got.Overall != vc.ConfidenceFailed {
		t.Errorf("overwrite: Overall = %v, want Failed", got.Overall)
	}
}
