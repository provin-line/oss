package wireauth

import (
	"testing"

	"github.com/provin-line/oss/did/dplaax"
)

// An audience is a registry ID, so the longest audience a verifier takes is
// the longest registry a did:dplaax DID may name.
func TestMaxAudienceLenIsTheRegistryBound(t *testing.T) {
	if maxAudienceLen != dplaax.MaxRegistryLen {
		t.Errorf("maxAudienceLen = %d, dplaax.MaxRegistryLen = %d", maxAudienceLen, dplaax.MaxRegistryLen)
	}
}
