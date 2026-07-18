package netcompose

import "testing"

type fakeHealthSource struct{ healthy bool }

func (f fakeHealthSource) StrippedPublishHealthy() bool { return f.healthy }

func TestByRefHealthGate(t *testing.T) {
	cases := []struct {
		name    string
		sources []StrippedPublishHealthSource
		want    bool
	}{
		{"no sources", nil, true},
		{"single healthy", []StrippedPublishHealthSource{fakeHealthSource{true}}, true},
		{"single unhealthy", []StrippedPublishHealthSource{fakeHealthSource{false}}, false},
		{"all healthy", []StrippedPublishHealthSource{fakeHealthSource{true}, fakeHealthSource{true}}, true},
		{"any unhealthy degrades the node", []StrippedPublishHealthSource{fakeHealthSource{true}, fakeHealthSource{false}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := NewByRefHealthGate(c.sources)
			if got := g.Healthy(); got != c.want {
				t.Errorf("Healthy() = %v, want %v", got, c.want)
			}
		})
	}
}
