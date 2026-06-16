package wireauth

import (
	"fmt"
	"time"

	"github.com/provin-line/oss/canon/jcs"
)

// ViewVersion is the frozen version of the signed-view composition. It is
// carried as "v" in the signed bytes; a verifier rejects any other version as
// ErrMalformedProof, so a future view-format change is a clean, detectable break
// rather than a silent canonicalization divergence across peers.
const ViewVersion = 1

// viewBytes builds the canonical signing scope of one ChainPeerService RPC and
// returns its JCS bytes. Sign and Verify both go through this single helper so
// the signed and reconstructed bytes are identical by construction.
//
// The composition is {signerDID, op, v, nonce, issuedAt, fields}: signerDID is
// bound into the signed bytes (a shared-key DID alias therefore cannot reuse
// another DID's signature), and issuedAt is rendered at second precision (the
// caller passes a second-truncated instant; the verifier rejects sub-second
// input before calling here). fields is validated against the value grammar
// (ErrInvalidView) so no canonical bytes are ever produced over a payload a peer
// implementation might canonicalize differently.
func viewBytes(signerDID, op, nonce string, issuedAt time.Time, fields map[string]any) ([]byte, error) {
	if err := validateFields(fields); err != nil {
		return nil, err
	}
	view := map[string]any{
		"signerDID": signerDID,
		"op":        op,
		"v":         ViewVersion,
		"nonce":     nonce,
		"issuedAt":  issuedAt.UTC().Format(time.RFC3339),
		"fields":    fields,
	}
	return jcs.Canonicalize(view)
}

// validateFields enforces the fields value grammar (D-w11): the payload must be
// a non-nil object whose values are string, bool, JSON null, or nested
// objects/arrays of those. Go numeric types are rejected — int vs float64 for
// the "same" field would canonicalize to different bytes, and JCS number
// serialization is an interop hazard for a frozen cross-org wire; number-like
// values must be carried as decimal strings by the per-op builder.
func validateFields(fields map[string]any) error {
	if fields == nil {
		return fmt.Errorf("%w: fields must be a non-nil object", ErrInvalidView)
	}
	for k, v := range fields {
		if err := validateFieldValue(v); err != nil {
			return fmt.Errorf("%w: at %q: %v", ErrInvalidView, k, err)
		}
	}
	return nil
}

func validateFieldValue(v any) error {
	switch t := v.(type) {
	case nil, string, bool:
		return nil
	case map[string]any:
		for k, e := range t {
			if err := validateFieldValue(e); err != nil {
				return fmt.Errorf("at %q: %v", k, err)
			}
		}
		return nil
	case []any:
		for i, e := range t {
			if err := validateFieldValue(e); err != nil {
				return fmt.Errorf("at [%d]: %v", i, err)
			}
		}
		return nil
	default:
		return fmt.Errorf("disallowed value type %T (numbers must be decimal strings)", v)
	}
}
