package conformance_test

import (
	"strings"
	"testing"
)

// TestCheckCoverage pins the coverage-completeness core: a pure function over
// (manifest, runner ids, skip ids) that reports every vector lacking exactly
// one of a runner or a skip, and every registered id absent from the manifest.
// It carries no global state and no execution order, so the guard cannot pass
// while coverage is silently partial.
func TestCheckCoverage(t *testing.T) {
	cases := []struct {
		name     string
		manifest []string
		runners  []string
		skips    []string
		want     []string // substrings each expected in exactly one problem
	}{
		{
			name:     "complete and consistent",
			manifest: []string{"canon-001", "process-004"},
			runners:  []string{"canon-001"},
			skips:    []string{"process-004"},
			want:     nil,
		},
		{
			name:     "missing runner and skip",
			manifest: []string{"canon-001", "resolver-001"},
			runners:  []string{"canon-001"},
			skips:    nil,
			want:     []string{"resolver-001"},
		},
		{
			name:     "both runner and skip",
			manifest: []string{"canon-001"},
			runners:  []string{"canon-001"},
			skips:    []string{"canon-001"},
			want:     []string{"canon-001"},
		},
		{
			name:     "orphan runner not in manifest",
			manifest: []string{"canon-001"},
			runners:  []string{"canon-001", "ghost-999"},
			skips:    nil,
			want:     []string{"ghost-999"},
		},
		{
			name:     "orphan skip not in manifest",
			manifest: []string{"canon-001"},
			runners:  []string{"canon-001"},
			skips:    []string{"ghost-999"},
			want:     []string{"ghost-999"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := checkCoverage(tc.manifest, tc.runners, tc.skips)
			if len(got) != len(tc.want) {
				t.Fatalf("checkCoverage returned %d problems %v, want %d %v", len(got), got, len(tc.want), tc.want)
			}
			for _, sub := range tc.want {
				found := 0
				for _, p := range got {
					if strings.Contains(p, sub) {
						found++
					}
				}
				if found != 1 {
					t.Errorf("problem mentioning %q appeared %d times, want exactly 1 (problems: %v)", sub, found, got)
				}
			}
		})
	}
}
