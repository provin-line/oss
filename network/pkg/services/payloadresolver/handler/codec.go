package handler

import (
	"errors"
	"fmt"
	"time"

	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
)

// errMalformedIssuedAt marks an AuthProof.issued_at that is not a canonical
// RFC 3339 UTC second-precision string. Mapped to InvalidArgument. Same strict
// codec the chain.v1 peer surface applies — reproduced here (not shared) so the
// two L2 surfaces stay decoupled, exactly as their handlers already are.
var errMalformedIssuedAt = errors.New("payloadresolver: malformed issued_at")

// decodeProof converts the wire AuthProof (reused from dplaax.chain.v1) to a
// wireauth.Proof, parsing issued_at through the strict codec. A nil proof is
// ErrMissingProof.
func decodeProof(ap *chainpb.AuthProof) (wireauth.Proof, error) {
	if ap == nil {
		return wireauth.Proof{}, wireauth.ErrMissingProof
	}
	issuedAt, err := parseIssuedAt(ap.GetIssuedAt())
	if err != nil {
		return wireauth.Proof{}, err
	}
	return wireauth.Proof{
		SignerDID: ap.GetSignerDid(),
		Nonce:     ap.GetNonce(),
		IssuedAt:  issuedAt,
		Signature: ap.GetSignature(),
	}, nil
}

// parseIssuedAt strictly decodes the wire issued_at string: it accepts ONLY the
// canonical RFC 3339 UTC second-precision form (the exact form wireauth signs
// over) and rejects fractional seconds, a non-Z offset, or any non-canonical
// string BEFORE the proof reaches wireauth.Verify.
func parseIssuedAt(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %q: %v", errMalformedIssuedAt, s, err)
	}
	if s != t.UTC().Format(time.RFC3339) {
		return time.Time{}, fmt.Errorf("%w: %q is not canonical UTC second-precision RFC 3339", errMalformedIssuedAt, s)
	}
	return t.UTC(), nil
}
