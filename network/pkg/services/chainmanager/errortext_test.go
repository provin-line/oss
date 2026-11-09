package chainmanager

import (
	"strings"
	"testing"

	"github.com/provin-line/oss/internal/netexcerpt"
)

// Connection info with a key this side does not use is refused with the key
// quoted within netexcerpt.ValueLimit bytes, however long the key.
func TestCheckConnectionInfo_NamesAnUnknownKeyWithinTheLimit(t *testing.T) {
	err := checkConnectionInfo(map[string]string{strings.Repeat("k\xff", 64<<10): "v"})
	if err == nil {
		t.Fatal("unknown key accepted")
	}
	if max := 80 + netexcerpt.ValueLimit; len(err.Error()) > max {
		t.Errorf("error of %d bytes, want at most %d: %.120q", len(err.Error()), max, err.Error())
	}
	if !strings.Contains(err.Error(), "… (") {
		t.Errorf("error %.120q does not give the key's length", err.Error())
	}
}
