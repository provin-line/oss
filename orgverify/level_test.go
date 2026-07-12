package orgverify

import "testing"

func TestEndorsementLevelValues(t *testing.T) {
	cases := []struct {
		level EndorsementLevel
		want  string
	}{
		{EndorsementVerified, "verified"},
		{EndorsementMissing, "missing"},
		{EndorsementInvalid, "invalid"},
		{EndorsementUnreachable, "unreachable"},
		{EndorsementNA, "na"},
	}
	for _, c := range cases {
		if got := string(c.level); got != c.want {
			t.Errorf("EndorsementLevel=%q, want %q", got, c.want)
		}
	}
}

// Exit codes are frozen (spec §7.2) — the numeric values must match exactly,
// not merely be distinct.
func TestEndorsementLevel_ExitCode(t *testing.T) {
	cases := []struct {
		level EndorsementLevel
		code  int
	}{
		{EndorsementVerified, 0},
		{EndorsementMissing, 1},
		{EndorsementInvalid, 2},
		{EndorsementUnreachable, 3},
		{EndorsementNA, 4},
	}
	for _, c := range cases {
		if got := c.level.ExitCode(); got != c.code {
			t.Errorf("EndorsementLevel(%s).ExitCode()=%d, want %d", c.level, got, c.code)
		}
	}
}

func TestEndorsementLevel_ExitCode_UnknownIsOutOfRange(t *testing.T) {
	if got := EndorsementLevel("bogus").ExitCode(); got >= 0 && got <= 4 {
		t.Errorf("unknown level ExitCode()=%d, want a value outside the defined 0-4 range", got)
	}
}

func TestResult_NotEndorsed(t *testing.T) {
	r := &Result{
		Level:  EndorsementMissing,
		Reason: ReasonDIDNotEndorsed,
		Detail: "DNS TXT records exist but did:dplaax:registry.attacker.dev:org:acme.com is not listed",
	}
	if r.Level != EndorsementMissing {
		t.Errorf("Level=%q, want %q", r.Level, EndorsementMissing)
	}
	if r.Reason != ReasonDIDNotEndorsed {
		t.Errorf("Reason=%q, want %q", r.Reason, ReasonDIDNotEndorsed)
	}
}
