// Package peerclient is the outbound side of the chainmanager connection flow:
// the ConnectRPC client this CM uses to call a remote publisher's
// ChainPeerService. It signs every call in-band with wireauth (as a configured
// node identity) and dials through an SSRF-guarded HTTP client; it satisfies
// chainmanager.PeerClient so the domain stays free of crypto and transport.
package peerclient

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/crypto"
	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	"github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
)

// op names — these MUST match the publisher verifier's per-op signed view
// (slice-11 D-p4); the bytes are reproduced via wireauth.Sign.
const (
	opGetPublisherInfo     = "GetPublisherInfo"
	opRegisterSubscription = "RegisterSubscription"
	opDisconnect           = "Disconnect"
)

// Client is a wireauth-signing ConnectRPC client for ChainPeerService. It signs
// as a single configured identity (signerDID + signer); the remote enforces the
// signer↔subscriber binding, so a request whose subscriber_did differs from
// signerDID is rejected end-to-end.
type Client struct {
	signer     crypto.Signer
	signerDID  string
	httpClient connect.HTTPClient
}

// New returns a Client that signs as signerDID using signer and dials through
// httpClient (supply an SSRF-guarded client, e.g. core.URLGuard.HTTPClient()).
func New(signer crypto.Signer, signerDID string, httpClient connect.HTTPClient) *Client {
	return &Client{signer: signer, signerDID: signerDID, httpClient: httpClient}
}

func (c *Client) peer(endpoint string) chainpbconnect.ChainPeerServiceClient {
	return chainpbconnect.NewChainPeerServiceClient(c.httpClient, endpoint)
}

// GetPublisherInfo discovers a publisher's transport + offered payload modes.
func (c *Client) GetPublisherInfo(ctx context.Context, endpoint, subscriberDID, publisherDID string) (string, []string, error) {
	ap, err := c.proof(opGetPublisherInfo, map[string]any{"publisher_did": publisherDID})
	if err != nil {
		return "", nil, err
	}
	resp, err := c.peer(endpoint).GetPublisherInfo(ctx, connect.NewRequest(&chainpb.GetPublisherInfoRequest{
		AuthProof:    ap,
		PublisherDid: publisherDID,
	}))
	if err != nil {
		return "", nil, mapRemoteErr(err)
	}
	return resp.Msg.GetPublishType(), resp.Msg.GetSupportedPayloadDelivery(), nil
}

// RegisterSubscription registers this subscriber against the publisher. The
// requested mode rides verbatim (empty stays empty); the publisher normalizes
// and returns the agreed mode.
func (c *Client) RegisterSubscription(ctx context.Context, endpoint, subscriberDID, publisherDID, requestedMode string) (string, map[string]string, string, string, error) {
	ap, err := c.proof(opRegisterSubscription, map[string]any{
		"subscriber_did":   subscriberDID,
		"publisher_did":    publisherDID,
		"payload_delivery": requestedMode,
	})
	if err != nil {
		return "", nil, "", "", err
	}
	resp, err := c.peer(endpoint).RegisterSubscription(ctx, connect.NewRequest(&chainpb.RegisterSubscriptionRequest{
		AuthProof:       ap,
		SubscriberDid:   subscriberDID,
		PublisherDid:    publisherDID,
		PayloadDelivery: requestedMode,
	}))
	if err != nil {
		return "", nil, "", "", mapRemoteErr(err)
	}
	return resp.Msg.GetSubscriptionId(), resp.Msg.GetConnectionInfo(), resp.Msg.GetPublishType(), resp.Msg.GetPayloadDelivery(), nil
}

// Disconnect tears down a remote subscription by its publisher-side id. A remote
// NotFound is surfaced as store.ErrNotFound so the domain can treat teardown as
// idempotent.
func (c *Client) Disconnect(ctx context.Context, endpoint, remoteSubscriptionID string) error {
	ap, err := c.proof(opDisconnect, map[string]any{"subscription_id": remoteSubscriptionID})
	if err != nil {
		return err
	}
	_, err = c.peer(endpoint).Disconnect(ctx, connect.NewRequest(&chainpb.DisconnectRequest{
		AuthProof:      ap,
		SubscriptionId: remoteSubscriptionID,
	}))
	if err != nil {
		return mapRemoteErr(err)
	}
	return nil
}

// proof signs op over fields as the configured identity and converts the
// wireauth.Proof to the wire AuthProof (issued_at as canonical second-precision
// UTC RFC3339 — the exact form the publisher's strict codec accepts).
func (c *Client) proof(op string, fields map[string]any) (*chainpb.AuthProof, error) {
	nonce, err := wireauth.NewNonce()
	if err != nil {
		return nil, fmt.Errorf("peerclient: nonce: %w", err)
	}
	p, err := wireauth.Sign(c.signer, c.signerDID, op, fields, nonce, time.Now())
	if err != nil {
		return nil, fmt.Errorf("peerclient: sign %s: %w", op, err)
	}
	return &chainpb.AuthProof{
		SignerDid: p.SignerDID,
		Nonce:     p.Nonce,
		IssuedAt:  p.IssuedAt.UTC().Format(time.RFC3339),
		Signature: p.Signature,
	}, nil
}

// mapRemoteErr maps a remote NotFound to store.ErrNotFound (so teardown is
// idempotent); any other failure is returned as-is for the domain to wrap.
func mapRemoteErr(err error) error {
	if connect.CodeOf(err) == connect.CodeNotFound {
		return fmt.Errorf("%w: %v", store.ErrNotFound, err)
	}
	return err
}

// compile-time guard: *Client satisfies the domain's PeerClient contract. The
// interface is declared in chainmanager; we assert structurally without importing
// it to avoid an import cycle (chainmanager → peerclient at wiring time).
var _ interface {
	GetPublisherInfo(ctx context.Context, endpoint, subscriberDID, publisherDID string) (string, []string, error)
	RegisterSubscription(ctx context.Context, endpoint, subscriberDID, publisherDID, requestedMode string) (string, map[string]string, string, string, error)
	Disconnect(ctx context.Context, endpoint, remoteSubscriptionID string) error
} = (*Client)(nil)
