package handler

import (
	"testing"
	"time"
)

func TestParseIssuedAt_Canonical(t *testing.T) {
	got, err := parseIssuedAt("2026-06-17T12:00:00Z")
	if err != nil {
		t.Fatalf("parseIssuedAt: %v", err)
	}
	want := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("parseIssuedAt = %v, want %v", got, want)
	}
}

func TestParseIssuedAt_Rejects(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"sub-second", "2026-06-17T12:00:00.5Z"},
		{"non-UTC offset", "2026-06-17T21:00:00+09:00"},
		{"zero offset not Z", "2026-06-17T12:00:00+00:00"},
		{"missing offset", "2026-06-17T12:00:00"},
		{"date only", "2026-06-17"},
		{"garbage", "not-a-time"},
		{"empty", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := parseIssuedAt(c.in); err == nil {
				t.Errorf("parseIssuedAt(%q) = nil error, want rejection", c.in)
			}
		})
	}
}
