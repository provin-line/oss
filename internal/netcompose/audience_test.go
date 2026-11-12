package netcompose

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	"github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/wireauth"
)

// audienceProbe signs a GetPublisherInfo proof for audience as a signer the
// node cannot resolve, and returns the node's answer. A proof for another
// audience is refused before the signer is resolved; a proof for the node's
// own audience gets past that check and fails later, on the signer.
func audienceProbe(t *testing.T, client chainpbconnect.ChainPeerServiceClient, audience string) error {
	t.Helper()
	signerDID := "did:dplaax:" + registryID + ":org:nobody"
	ks := filestore.New(t.TempDir())
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := ks.SaveKeyPair(signerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: kp}); err != nil {
		t.Fatalf("save: %v", err)
	}
	nonce, err := wireauth.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{"publisher_did": ownerDID + ":pipeline:p1"}
	p, err := wireauth.Sign(ks, signerDID, audience, "GetPublisherInfo", fields, nonce, time.Now())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	_, err = client.GetPublisherInfo(context.Background(), connect.NewRequest(&chainpb.GetPublisherInfoRequest{
		AuthProof: &chainpb.AuthProof{
			SignerDid: p.SignerDID, Audience: p.Audience, Nonce: p.Nonce,
			IssuedAt: p.IssuedAt.UTC().Format(time.RFC3339), Signature: p.Signature,
		},
		PublisherDid: ownerDID + ":pipeline:p1",
	}))
	return err
}

func refusedForAudience(err error) bool {
	return err != nil && strings.Contains(err.Error(), "proof is for another audience")
}

func TestPeerVerifierAudienceIsRegistryID(t *testing.T) {
	srv, _, _ := assembledWith(t, 1<<20)
	client := chainpbconnect.NewChainPeerServiceClient(srv.Client(), srv.URL)
	if err := audienceProbe(t, client, "other.example"); !refusedForAudience(err) || connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("a proof for another registry: %v (code %v), want Unauthenticated for the audience", err, connect.CodeOf(err))
	}
	if err := audienceProbe(t, client, registryID); refusedForAudience(err) {
		t.Fatalf("a proof for the node's registry ID was refused for its audience: %v", err)
	}
}

// The audience is the node's registry ID, not anything about the request's
// URL: a reverse proxy that changes the Host and serves the node under a path
// prefix makes no difference.
func TestPeerSurfaceBehindProxyAcceptsOwnAudience(t *testing.T) {
	node, _, _ := assembledWith(t, 1<<20)
	target, err := url.Parse(node.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	direct := proxy.Director
	proxy.Director = func(r *http.Request) {
		direct(r)
		r.Host = "public.example"
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/edge")
	}
	front := httptest.NewServer(proxy)
	t.Cleanup(front.Close)
	client := chainpbconnect.NewChainPeerServiceClient(front.Client(), front.URL+"/edge")
	if err := audienceProbe(t, client, registryID); refusedForAudience(err) {
		t.Fatalf("through the proxy, a proof for the node's registry ID was refused for its audience: %v", err)
	}
	if err := audienceProbe(t, client, "public.example"); !refusedForAudience(err) {
		t.Fatalf("through the proxy, a proof for the proxy's host: %v, want refused for its audience", err)
	}
}
