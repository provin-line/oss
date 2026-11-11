package chainmanager

import (
	"context"
	"fmt"
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

// A DID the chain manager refuses for its form is quoted within
// netexcerpt.ValueLimit bytes, however long the DID: a pipeline DID that does
// not parse or is not a pipeline's, a subscriber DID, a publisher DID.
func TestDIDsRefusedForTheirFormAreNamedWithinTheLimit(t *testing.T) {
	owner := "did:dplaax:poc.dplaax.dev:org:" + strings.Repeat("x", 64<<10)
	unparsable := owner + "!"
	svc, _ := subSvc(&fakeInfra{}, defaultPeer(), publicGuard())
	_, subscribeErr := svc.Subscribe(context.Background(), unparsable, pubPipeline, "inline")
	_, _, targetErr := svc.resolveTarget(context.Background(), unparsable)
	named := map[string]string{
		"an unparsable pipeline DID":   unparsable,
		"a pipeline DID that is not":   owner,
		"an unparsable subscriber DID": unparsable,
		"an unparsable publisher DID":  unparsable,
	}
	for name, err := range map[string]error{
		"an unparsable pipeline DID":   requirePipelineDID(unparsable),
		"a pipeline DID that is not":   requirePipelineDID(owner),
		"an unparsable subscriber DID": subscribeErr,
		"an unparsable publisher DID":  targetErr,
	} {
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if max := 80 + netexcerpt.ValueLimit + 2*netexcerpt.ValueLimit; len(err.Error()) > max {
			t.Errorf("%s: error of %d bytes, want at most %d: %.120q", name, len(err.Error()), max, err.Error())
		}
		if !strings.Contains(err.Error(), fmt.Sprintf("… (%d bytes)", len(named[name]))) {
			t.Errorf("%s: error %.120q does not give the DID's length", name, err.Error())
		}
	}
}
