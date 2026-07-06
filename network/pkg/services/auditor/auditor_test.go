package auditor_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/vc"
)

func TestMemStatusStore_RoundTrip(t *testing.T) {
	s := auditor.NewMemStatusStore()

	if _, err := s.Get("absent"); !errors.Is(err, auditor.ErrNotFound) {
		t.Errorf("absent head: got %v, want ErrNotFound", err)
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
	got, err := s.Get("sha256:h")
	if err != nil {
		t.Fatalf("present head: %v", err)
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
