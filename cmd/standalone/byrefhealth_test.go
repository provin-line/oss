package main

import "testing"

type fakeHealthSource struct{ healthy bool }

func (f fakeHealthSource) StrippedPublishHealthy() bool { return f.healthy }

func TestByRefHealthGate(t *testing.T) {
	cases := []struct {
		name    string
		sources []strippedPublishHealthSource
		want    bool
	}{
		{"no sources", nil, true},
		{"single healthy", []strippedPublishHealthSource{fakeHealthSource{true}}, true},
		{"single unhealthy", []strippedPublishHealthSource{fakeHealthSource{false}}, false},
		{"all healthy", []strippedPublishHealthSource{fakeHealthSource{true}, fakeHealthSource{true}}, true},
		{"any unhealthy degrades the node", []strippedPublishHealthSource{fakeHealthSource{true}, fakeHealthSource{false}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newByRefHealthGate(c.sources)
			if got := g.Healthy(); got != c.want {
				t.Errorf("Healthy() = %v, want %v", got, c.want)
			}
		})
	}
}
