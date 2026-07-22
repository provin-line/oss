package main

import (
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	natstest "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nkeys"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	"github.com/provin-line/oss/vc"
)

// This file's helpers are a deliberate DUPLICATE of pipeline/runtime's
// identically-named test helpers (dataplane_test.go, moved there in the
// pipeline/runtime extraction): a Go _test.go identifier is invisible outside
// its own package's test binary, so once dataplane.go's white-box tests moved
// into package runtime, cmd/standalone's composition-level e2e tests — which
// build a *pipelineruntime.Runtime through the exported Build/Deps surface,
// not the moved package's internals — lost access to the shared fixtures they
// still need (an embedded single-account nats-server, a keystore, a minimal
// source pipeline config). Kept behaviorally identical to the pipeline/runtime
// originals.

// dpVCStore returns a fresh in-memory vcresolver.Service for use in data-plane
// tests that build consuming loops (slice-17f: all consuming loops require a
// VCStore).
func dpVCStore() *vcresolver.Service {
	return vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), memstore.NewPool())
}

// dpAccountServer embeds a single-account operator-trusted nats-server and returns
// its URL plus the account seed (the node's data-plane identity).
func dpAccountServer(t *testing.T) (url, accountSeed string) {
	t.Helper()
	op, _ := nkeys.CreateOperator()
	opPub, _ := op.PublicKey()
	acc, _ := nkeys.CreateAccount()
	accPub, _ := acc.PublicKey()
	accSeed, _ := acc.Seed()
	ac := jwt.NewAccountClaims(accPub)
	ajwt, err := ac.Encode(op)
	if err != nil {
		t.Fatalf("encode account JWT: %v", err)
	}
	mr := &server.MemAccResolver{}
	if err := mr.Store(accPub, ajwt); err != nil {
		t.Fatalf("resolver store: %v", err)
	}
	s := natstest.RunServer(&server.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
		TrustedKeys: []string{opPub}, AccountResolver: mr,
	})
	t.Cleanup(s.Shutdown)
	return s.ClientURL(), string(accSeed)
}

const (
	dpPipelineDID = "did:dplaax:reg:org:acme:pipeline:pipe"
	dpIssuerDID   = "did:dplaax:reg:org:acme:pipeline:pipe:process:src"
	dpIngress     = "ingest.src"
)

func dpKeyStore(t *testing.T) keystore.KeyStore {
	t.Helper()
	ks := filestore.New(t.TempDir())
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if err := ks.SaveKeyPair(dpIssuerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
		t.Fatalf("save key: %v", err)
	}
	return ks
}

func dpPipelineCfg() *pipelineconfig.Config {
	return &pipelineconfig.Config{Loops: []pipelineconfig.LoopConfig{{
		Name:           "src",
		Role:           pipelineconfig.RoleSource,
		IngressSubject: dpIngress,
		Source: pipelineconfig.SourceConfig{
			OutputSubject: dpPipelineDID,
			Issuer: pipelineconfig.IssuerConfig{
				DID: dpIssuerDID, KeyID: string(keystore.KeyIDSigning),
				VerificationMethod: dpIssuerDID + "#signing",
			},
			PipelineID:          "pipe",
			ProcessID:           "src",
			TransformationClaim: vc.ClaimConvert,
		},
	}}}
}
