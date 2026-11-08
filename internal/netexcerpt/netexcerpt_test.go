package netexcerpt_test

import (
	"testing"

	"github.com/provin-line/oss/internal/excerpt"
	"github.com/provin-line/oss/internal/netexcerpt"
)

// Both limits are ones package excerpt takes, and a whole text has room for
// more than one named value.
func TestLimits(t *testing.T) {
	if netexcerpt.ValueLimit < excerpt.MinLimit {
		t.Errorf("ValueLimit %d is under excerpt.MinLimit %d", netexcerpt.ValueLimit, excerpt.MinLimit)
	}
	if netexcerpt.TextLimit < 2*netexcerpt.ValueLimit {
		t.Errorf("TextLimit %d has no room for two values of ValueLimit %d", netexcerpt.TextLimit, netexcerpt.ValueLimit)
	}
}
