package wireauth

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/provin-line/oss/canon/jcs"
	"github.com/provin-line/oss/internal/excerpt"
	"github.com/provin-line/oss/internal/jsondepth"
)

// ViewVersion is the frozen version of the signed-view composition, folded
// into the signed bytes as "v". The version is not carried on the wire: the
// verifier always reconstructs the view with this constant, so a signer using
// any other version fails signature verification (ErrSignatureInvalid) — a
// clean, detectable break rather than a silent canonicalization divergence
// across peers.
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
	return jcs.CanonicalizeRFC8785(view)
}

// validateFields enforces the fields value grammar (D-w11): the payload must be
// a non-nil object whose values are string, bool, JSON null, or nested
// objects/arrays of those. Go numeric types are rejected — int vs float64 for
// the "same" field would canonicalize to different bytes, and JCS number
// serialization is an interop hazard for a frozen cross-org wire; number-like
// values must be carried as decimal strings by the per-op builder.
//
// The view holds the fields one level down, so the fields may nest at most
// jsondepth.Max-1 objects and arrays, the fields object counted, and the view
// at most jsondepth.Max: the check recurses once per level and refuses deeper
// fields before entering the level past the bound, as a goroutine stack
// exhausted is a fatal error, so what passes is copied and canonicalized
// without a refusal. The refusal names the path to the value, spelled once
// and within fieldPathLimit bytes.
func validateFields(fields map[string]any) error {
	if fields == nil {
		return fmt.Errorf("%w: fields must be a non-nil object", ErrInvalidView)
	}
	var path []string
	for k, v := range fields {
		path = append(path[:0], strconv.Quote(k))
		if err := validateFieldValue(v, 3, &path); err != nil {
			at, _ := excerpt.Of("at "+strings.Join(path, ": at "), fieldPathLimit)
			return fmt.Errorf("%w: %s: %v", ErrInvalidView, at, err)
		}
	}
	return nil
}

// fieldPathLimit bounds the path a refusal of the fields names.
const fieldPathLimit = 256

// validateFieldValue checks v, held depth objects and arrays deep in the view.
// path is where v is: a step is pushed before a member or item is checked and
// popped after, and left as it is on a refusal, for validateFields to spell.
func validateFieldValue(v any, depth int, path *[]string) error {
	switch t := v.(type) {
	case nil, string, bool:
		return nil
	case map[string]any:
		if depth > jsondepth.Max {
			return errFieldsTooDeep
		}
		for k, e := range t {
			*path = append(*path, strconv.Quote(k))
			if err := validateFieldValue(e, depth+1, path); err != nil {
				return err
			}
			*path = (*path)[:len(*path)-1]
		}
		return nil
	case []any:
		if depth > jsondepth.Max {
			return errFieldsTooDeep
		}
		for i, e := range t {
			*path = append(*path, "["+strconv.Itoa(i)+"]")
			if err := validateFieldValue(e, depth+1, path); err != nil {
				return err
			}
			*path = (*path)[:len(*path)-1]
		}
		return nil
	default:
		return fmt.Errorf("disallowed value type %T (numbers must be decimal strings)", v)
	}
}

// errFieldsTooDeep refuses fields nested past the bound (validateFields).
var errFieldsTooDeep = fmt.Errorf("nested deeper than %d objects and arrays, the view counted", jsondepth.Max)
