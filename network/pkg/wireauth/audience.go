package wireauth

import (
	"fmt"

	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/internal/excerpt"
)

// AudienceForDID is the audience of the node that serves did: the registry
// ID that a proof sent to that node names (Claims.Audience) and that the
// node's verifier accepts (VerifierConfig.Audience). For a did:dplaax DID it
// is the DID's registry segment, the registry that answers for the DID's
// document and whose node serves its endpoints. A sender that derives an
// audience from a DID derives it here. A DID that does not parse as
// did:dplaax is an error naming it, within a bound, with the parser's reason.
func AudienceForDID(did string) (string, error) {
	d, err := dplaax.Parse(did)
	if err != nil {
		return "", fmt.Errorf("wireauth: %s does not parse as a did:dplaax DID, so the audience of its node is unknown: %w", excerpt.Quoted(did, 128), err)
	}
	return d.Registry, nil
}
