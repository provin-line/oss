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
	"github.com/provin-line/oss/network/internal/authproof"
	"github.com/provin-line/oss/network/pkg/services/chainmanager"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
)

// op names — these MUST match the publisher verifier's per-op signed view; the
// bytes are reproduced via wireauth.Sign.
const (
	opGetPublisherInfo     = "GetPublisherInfo"
	opRegisterSubscription = "RegisterSubscription"
	opDisconnect           = "Disconnect"
)

// A publisher is another organization's server, so the client bounds what it
// takes from one: it accepts no compression, maxResponseBytes bounds a
// response (every ChainPeerService response is a few small fields, and a
// publisher's handler reads requests within the same 256 KiB), and
// callTimeout bounds a call whatever the caller's context (the subscriber's
// compensating Disconnect runs under one that is never cancelled, while the
// chain manager holds its lock).
const (
	maxResponseBytes = 256 << 10
	callTimeout      = 30 * time.Second
)

// Client is a wireauth-signing ConnectRPC client for ChainPeerService. It signs
// as a single configured identity (signerDID + signer); the remote enforces the
// signer↔subscriber binding, so a request whose subscriber_did differs from
// signerDID is rejected end-to-end.
type Client struct {
	signer      crypto.Signer
	signerDID   string
	httpClient  connect.HTTPClient
	callTimeout time.Duration
}

// New returns a Client that signs as signerDID using signer and dials through
// httpClient (supply an SSRF-guarded client, e.g. core.URLGuard.HTTPClient()).
func New(signer crypto.Signer, signerDID string, httpClient connect.HTTPClient) *Client {
	return &Client{signer: signer, signerDID: signerDID, httpClient: httpClient, callTimeout: callTimeout}
}

func (c *Client) peer(endpoint string) chainpbconnect.ChainPeerServiceClient {
	return chainpbconnect.NewChainPeerServiceClient(c.httpClient, endpoint,
		connect.WithAcceptCompression("gzip", nil, nil),
		connect.WithReadMaxBytes(maxResponseBytes))
}

// Client is the chain manager's PeerClient: it implements the contract
// chainmanager defines, whose Peer it takes.
var _ chainmanager.PeerClient = (*Client)(nil)

// GetPublisherInfo discovers a publisher's transport + offered payload modes.
// Each call goes to to.Endpoint with a proof for to.Audience (see
// chainmanager.Peer).
func (c *Client) GetPublisherInfo(ctx context.Context, to chainmanager.Peer, subscriberDID, publisherDID string) (string, []string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.callTimeout)
	defer cancel()
	ap, err := c.proof(to.Audience, opGetPublisherInfo, map[string]any{"publisher_did": publisherDID})
	if err != nil {
		return "", nil, err
	}
	resp, err := c.peer(to.Endpoint).GetPublisherInfo(ctx, connect.NewRequest(&chainpb.GetPublisherInfoRequest{
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
func (c *Client) RegisterSubscription(ctx context.Context, to chainmanager.Peer, subscriberDID, publisherDID, requestedMode string) (string, map[string]string, string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.callTimeout)
	defer cancel()
	ap, err := c.proof(to.Audience, opRegisterSubscription, map[string]any{
		"subscriber_did":   subscriberDID,
		"publisher_did":    publisherDID,
		"payload_delivery": requestedMode,
	})
	if err != nil {
		return "", nil, "", "", err
	}
	resp, err := c.peer(to.Endpoint).RegisterSubscription(ctx, connect.NewRequest(&chainpb.RegisterSubscriptionRequest{
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
func (c *Client) Disconnect(ctx context.Context, to chainmanager.Peer, remoteSubscriptionID string) error {
	ctx, cancel := context.WithTimeout(ctx, c.callTimeout)
	defer cancel()
	ap, err := c.proof(to.Audience, opDisconnect, map[string]any{"subscription_id": remoteSubscriptionID})
	if err != nil {
		return err
	}
	_, err = c.peer(to.Endpoint).Disconnect(ctx, connect.NewRequest(&chainpb.DisconnectRequest{
		AuthProof:      ap,
		SubscriptionId: remoteSubscriptionID,
	}))
	if err != nil {
		return mapRemoteErr(err)
	}
	return nil
}

// proof signs op over fields as the configured identity, for audience (the
// publisher node's, chainmanager.Peer), in the proof's one wire form
// (network/internal/authproof).
func (c *Client) proof(audience, op string, fields map[string]any) (*chainpb.AuthProof, error) {
	ap, err := authproof.Sign(c.signer, op, fields, c.signerDID, audience)
	if err != nil {
		return nil, fmt.Errorf("peerclient: %w", err)
	}
	return ap, nil
}

// mapRemoteErr maps a remote NotFound to store.ErrNotFound (so teardown is
// idempotent); any other failure is returned as-is for the domain to wrap.
func mapRemoteErr(err error) error {
	if connect.CodeOf(err) == connect.CodeNotFound {
		return fmt.Errorf("%w: %v", store.ErrNotFound, err)
	}
	return err
}
