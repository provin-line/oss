// Package client is the production crypto.Signer that routes signing to a remote
// SignerService, so private keys stay server-side (the KMS model). A pipeline
// process holds a DID, not a key; it signs by calling this adapter, which calls
// the registry's SignerService.
//
// It imports only the generated client, crypto (the seam it satisfies), and
// keystore (the leaf key-ID contract) — never the signer service domain — so the
// dependency points inward and there is no service-to-service cycle.
package client

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/crypto"
	signerpb "github.com/provin-line/oss/gen/go/dplaax/signer/v1"
	"github.com/provin-line/oss/gen/go/dplaax/signer/v1/signerpbconnect"
	"github.com/provin-line/oss/keystore"
)

// ErrUnsupportedKeyID is returned by Sign when keyID is neither "signing" nor
// "auth": the adapter dispatches to a signing-domain RPC by keyID and has no RPC
// for any other key. It is client-local by design (the package never reaches
// into the signer domain for a sentinel).
var ErrUnsupportedKeyID = errors.New("signer/client: unsupported key id")

// Signer is a crypto.Signer backed by a remote SignerService. It dispatches by
// keyID — the inverse of the server's domain binding: "signing" → Sign (VC proof
// domain), "auth" → SignRaw (L2 wire domain) — and returns the raw signature
// bytes (the vc layer applies multibase framing).
type Signer struct {
	client signerpbconnect.SignerServiceClient
}

var _ crypto.Signer = (*Signer)(nil)

// New returns a Signer over the given SignerService client.
func New(c signerpbconnect.SignerServiceClient) *Signer {
	return &Signer{client: c}
}

// Sign signs data under (did, keyID) via the remote service. The crypto.Signer
// seam carries no context, so calls use context.Background() — the same place
// the seam already drops ctx (vc.CreateProof calls Sign without one).
func (s *Signer) Sign(did, keyID string, data []byte) ([]byte, error) {
	ctx := context.Background()
	switch keyID {
	case string(keystore.KeyIDSigning):
		resp, err := s.client.Sign(ctx, connect.NewRequest(&signerpb.SignRequest{
			Did: did, KeyId: keyID, Data: data,
		}))
		if err != nil {
			return nil, err
		}
		return resp.Msg.GetSignature(), nil
	case string(keystore.KeyIDAuth):
		resp, err := s.client.SignRaw(ctx, connect.NewRequest(&signerpb.SignRawRequest{
			Did: did, KeyId: keyID, Data: data,
		}))
		if err != nil {
			return nil, err
		}
		return resp.Msg.GetSignature(), nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedKeyID, keyID)
	}
}
