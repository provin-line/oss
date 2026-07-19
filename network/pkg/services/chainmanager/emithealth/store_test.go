package emithealth_test

import (
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/services/chainmanager/emithealth"
)

const (
	pub1 = "did:dplaax:reg:org:acme:pipeline:p1"
	pub2 = "did:dplaax:reg:org:acme:pipeline:p2"
)

func TestState_NeverReported(t *testing.T) {
	s := emithealth.New(90 * time.Second)
	if got := s.State(pub1, time.Now()); got != emithealth.NeverReported {
		t.Errorf("state = %v, want NeverReported", got)
	}
}

func TestState_HealthyReported(t *testing.T) {
	s := emithealth.New(90 * time.Second)
	now := time.Now()
	s.Report(pub1, true, now)
	if got := s.State(pub1, now); got != emithealth.HealthyReported {
		t.Errorf("state = %v, want HealthyReported", got)
	}
}

func TestState_UnhealthyReported(t *testing.T) {
	s := emithealth.New(90 * time.Second)
	now := time.Now()
	s.Report(pub1, false, now)
	if got := s.State(pub1, now); got != emithealth.UnhealthyReported {
		t.Errorf("state = %v, want UnhealthyReported", got)
	}
}

// The TTL boundary is pinned: a report exactly ttl old is ALREADY Expired
// (inclusive), one nanosecond younger is still fresh, and past ttl stays
// Expired.
func TestState_TTLBoundary(t *testing.T) {
	const ttl = 90 * time.Second
	s := emithealth.New(ttl)
	base := time.Now()
	s.Report(pub1, true, base)

	cases := []struct {
		name string
		now  time.Time
		want emithealth.HealthState
	}{
		{"one nanosecond before ttl elapses", base.Add(ttl - time.Nanosecond), emithealth.HealthyReported},
		{"exactly at ttl", base.Add(ttl), emithealth.Expired},
		{"one nanosecond past ttl", base.Add(ttl + time.Nanosecond), emithealth.Expired},
		{"well past ttl", base.Add(10 * ttl), emithealth.Expired},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := s.State(pub1, c.now); got != c.want {
				t.Errorf("state = %v, want %v", got, c.want)
			}
		})
	}
}

// A report is a point-in-time snapshot: a later Report call replaces the
// prior one for that publisher rather than aggregating.
func TestReport_OverwritesPriorReport(t *testing.T) {
	s := emithealth.New(90 * time.Second)
	now := time.Now()
	s.Report(pub1, false, now)
	s.Report(pub1, true, now.Add(time.Second))
	if got := s.State(pub1, now.Add(time.Second)); got != emithealth.HealthyReported {
		t.Errorf("state after overwrite = %v, want HealthyReported", got)
	}
}

// Reports are tracked per publisher: reporting for one publisher must not
// affect another's (still-NeverReported) state.
func TestState_PerPublisherIndependent(t *testing.T) {
	s := emithealth.New(90 * time.Second)
	now := time.Now()
	s.Report(pub1, true, now)
	if got := s.State(pub2, now); got != emithealth.NeverReported {
		t.Errorf("unreported publisher state = %v, want NeverReported", got)
	}
	if got := s.State(pub1, now); got != emithealth.HealthyReported {
		t.Errorf("reported publisher state = %v, want HealthyReported", got)
	}
}

// NeverReported is the zero value of HealthState (AGENTS.md: zero values fail
// closed) — pinned so a future reordering of the const block cannot silently
// flip an unrecognized publisher into reading as a positive health claim.
func TestNeverReported_IsZeroValue(t *testing.T) {
	var zero emithealth.HealthState
	if zero != emithealth.NeverReported {
		t.Errorf("zero value = %v, want NeverReported (%v)", zero, emithealth.NeverReported)
	}
}
