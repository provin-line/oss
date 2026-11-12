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
	s.Report(pub1, true, now, now)
	if got := s.State(pub1, now); got != emithealth.HealthyReported {
		t.Errorf("state = %v, want HealthyReported", got)
	}
}

func TestState_UnhealthyReported(t *testing.T) {
	s := emithealth.New(90 * time.Second)
	now := time.Now()
	s.Report(pub1, false, now, now)
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
	s.Report(pub1, true, base, base)

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

// A report is a point-in-time snapshot: a report made later replaces the
// prior one for that publisher rather than aggregating.
func TestReport_OverwritesPriorReport(t *testing.T) {
	s := emithealth.New(90 * time.Second)
	now := time.Now()
	s.Report(pub1, false, now, now)
	s.Report(pub1, true, now.Add(time.Second), now.Add(time.Second))
	if got := s.State(pub1, now.Add(time.Second)); got != emithealth.HealthyReported {
		t.Errorf("state after overwrite = %v, want HealthyReported", got)
	}
}

// A report stays fresh for ttl from when this node received it, not from
// when it was made.
func TestState_FreshnessRunsFromReceipt(t *testing.T) {
	const ttl = 90 * time.Second
	s := emithealth.New(ttl)
	received := time.Now()
	s.Report(pub1, true, received.Add(-50*time.Second), received)
	if got := s.State(pub1, received.Add(ttl-time.Nanosecond)); got != emithealth.HealthyReported {
		t.Errorf("state just before ttl after receipt = %v, want HealthyReported", got)
	}
	if got := s.State(pub1, received.Add(ttl)); got != emithealth.Expired {
		t.Errorf("state ttl after receipt = %v, want Expired", got)
	}
}

// A report made before the one on record is dropped when it arrives after it
// (the other order is TestReport_OverwritesPriorReport): the recorded report's
// value stands, and its freshness still runs from when it was received.
func TestReport_DropsAReportMadeBeforeTheRecordedOne(t *testing.T) {
	const ttl = 90 * time.Second
	s := emithealth.New(ttl)
	made, received := time.Now(), time.Now()
	s.Report(pub1, true, made, received)
	s.Report(pub1, false, made.Add(-time.Second), received.Add(30*time.Second))
	if got := s.State(pub1, received.Add(30*time.Second)); got != emithealth.HealthyReported {
		t.Errorf("state after an earlier-made report = %v, want HealthyReported", got)
	}
	if got := s.State(pub1, received.Add(ttl-time.Nanosecond)); got != emithealth.HealthyReported {
		t.Errorf("state just before ttl after the recorded report's receipt = %v, want HealthyReported", got)
	}
	if got := s.State(pub1, received.Add(ttl)); got != emithealth.Expired {
		t.Errorf("state ttl after the recorded report's receipt = %v, want Expired (a dropped report gives no freshness)", got)
	}
}

// Reports are ordered by when they were made, compared with when the recorded
// one was made, not with when it was received: a publisher whose clock runs
// behind the node's makes each report earlier than the node received the last,
// and its next report, made later, still replaces it.
func TestReport_OrdersByWhenTheRecordedReportWasMade(t *testing.T) {
	s := emithealth.New(90 * time.Second)
	made := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	received := made.Add(40 * time.Second)
	s.Report(pub1, false, made, received)
	s.Report(pub1, true, made.Add(10*time.Second), received.Add(10*time.Second))
	if got := s.State(pub1, received.Add(10*time.Second)); got != emithealth.HealthyReported {
		t.Errorf("state after a later-made report = %v, want HealthyReported", got)
	}
}

// Two reports made at the same instant (issued_at has second precision) are
// taken in the order Report is called: the later call replaces the earlier,
// and its freshness runs from its own receipt.
func TestReport_ReplacesAReportMadeAtTheSameInstant(t *testing.T) {
	const ttl = 90 * time.Second
	s := emithealth.New(ttl)
	made := time.Now()
	s.Report(pub1, true, made, made)
	s.Report(pub1, false, made, made.Add(30*time.Second))
	if got := s.State(pub1, made.Add(ttl)); got != emithealth.UnhealthyReported {
		t.Errorf("state ttl after the first receipt = %v, want UnhealthyReported (fresh from the second)", got)
	}
}

// Reports are tracked per publisher: reporting for one publisher must not
// affect another's (still-NeverReported) state.
func TestState_PerPublisherIndependent(t *testing.T) {
	s := emithealth.New(90 * time.Second)
	now := time.Now()
	s.Report(pub1, true, now, now)
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
