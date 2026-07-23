package commands

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/cmd/provin/internal/keyfile"
	"github.com/provin-line/oss/delegation"
	didpb "github.com/provin-line/oss/gen/go/dplaax/did/v1"
)

// ExternalKeys carries the caller's LOCALLY-minted #auth/#signing public keys
// for the external-key issuance path (raw 32-byte Ed25519, matching
// didregistry.ExternalPublicKeys exactly): passing a non-nil ExternalKeys to
// PipelineCreate/ProcessCreate switches issuance so the registry registers
// THESE public halves and never generates or stores a private key for the
// target DID — the separated-topology model, where the private halves live
// only in cmd/pipeline's own local keystore (never the registry's). nil (the
// default) keeps the KMS mint-mode registration issue's own doc describes.
type ExternalKeys struct {
	AuthPublicKey    []byte
	SigningPublicKey []byte
}

// externalKeysFileEntry is one DID's exported public halves in the JSON
// shape LoadExternalKeys reads and deploy/quickstart/provision writes
// (base64-standard-encoded raw Ed25519 public keys) — the wire format
// between the quickstart's provisioner (which mints the keys into
// cmd/pipeline's own data volume and never lets the private halves leave it)
// and this CLI (which only ever needs the public halves, to submit over
// IssuePipelineRequest/IssueProcessRequest's external_public_keys).
type externalKeysFileEntry struct {
	AuthPublicKey    string `json:"auth_public_key"`
	SigningPublicKey string `json:"signing_public_key"`
}

// LoadExternalKeys reads path (a JSON object keyed by subject DID, each
// value an externalKeysFileEntry) and returns targetDID's entry as
// ExternalKeys. This is the CLI-side half of the external-key issuance path:
// the file itself is produced out-of-band (deploy/quickstart/provision is
// today's one producer) by a process that minted the keypair LOCALLY, in
// whatever local keystore the DID's eventual signer reads from, and exported
// only the public halves here — this function never sees, and this package
// never handles, a private key for the DID being issued.
func LoadExternalKeys(path, targetDID string) (*ExternalKeys, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("external keys: read %s: %w", path, err)
	}
	// The export file is a trust boundary (it decides what public key this
	// CLI submits for the target DID to hold), so it gets the same strict
	// gate keyfile.Load uses for owner keys: duplicate members or trailing
	// data are rejected, not last-wins merged.
	var file map[string]externalKeysFileEntry
	if err := canon.NewStrictDecoder(raw).Decode(&file); err != nil {
		return nil, fmt.Errorf("external keys: parse %s: %w", path, err)
	}
	entry, ok := file[targetDID]
	if !ok {
		return nil, fmt.Errorf("external keys: %s has no entry for %s", path, targetDID)
	}
	authPub, err := base64.StdEncoding.DecodeString(entry.AuthPublicKey)
	if err != nil {
		return nil, fmt.Errorf("external keys: %s: %s: decode auth_public_key: %w", path, targetDID, err)
	}
	signPub, err := base64.StdEncoding.DecodeString(entry.SigningPublicKey)
	if err != nil {
		return nil, fmt.Errorf("external keys: %s: %s: decode signing_public_key: %w", path, targetDID, err)
	}
	if len(authPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("external keys: %s: %s: auth_public_key is %d bytes, want %d", path, targetDID, len(authPub), ed25519.PublicKeySize)
	}
	if len(signPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("external keys: %s: %s: signing_public_key is %d bytes, want %d", path, targetDID, len(signPub), ed25519.PublicKeySize)
	}
	return &ExternalKeys{AuthPublicKey: authPub, SigningPublicKey: signPub}, nil
}

// PipelineCreate issues a pipeline DID under the owner held at ownerKeyPath:
// the owner signs a delegation credential for targetDID. external nil keeps
// the KMS model (the registry generates + holds the pipeline's signing
// keys — no new private key reaches the client); a non-nil external switches
// to the external-key path (see ExternalKeys' doc) — the registry registers
// external's public halves and mints nothing of its own.
func PipelineCreate(ctx context.Context, env Env, targetDID, ownerKeyPath string, external *ExternalKeys) error {
	return issue(ctx, env, targetDID, ownerKeyPath, "pipeline", external)
}

// ProcessCreate issues a process DID under the owner held at ownerKeyPath
// (same delegation flow and external-key switch as PipelineCreate).
func ProcessCreate(ctx context.Context, env Env, targetDID, ownerKeyPath string, external *ExternalKeys) error {
	return issue(ctx, env, targetDID, ownerKeyPath, "process", external)
}

func issue(ctx context.Context, env Env, targetDID, ownerKeyPath, kind string, external *ExternalKeys) error {
	key, err := keyfile.Load(ownerKeyPath)
	if err != nil {
		return err
	}
	dlg, err := delegation.Build(key.Signer(), key.DID, delegation.DelegationSubject{
		ID: targetDID, DelegatedBy: key.DID,
	})
	if err != nil {
		return fmt.Errorf("%s create: build delegation for %s: %w", kind, targetDID, err)
	}
	// Wire encoding only, not a signing scope: delegation.Build already
	// computed the proof over cred.signingBody() above, and delegation.Verify
	// re-derives that same canonical body from the RECEIVED struct's own
	// fields (not from these wire bytes) to check it — mirrors owner.go's
	// identical marshal-for-transport of an already-signed document
	// (canonicalizer-hygiene-exempt).
	dlgBytes, err := json.Marshal(dlg)
	if err != nil {
		return fmt.Errorf("%s create: marshal delegation: %w", kind, err)
	}
	c, err := env.didClient()
	if err != nil {
		return err
	}
	var extpb *didpb.ExternalPublicKeys
	if external != nil {
		extpb = &didpb.ExternalPublicKeys{
			AuthPublicKey:    external.AuthPublicKey,
			SigningPublicKey: external.SigningPublicKey,
		}
	}
	switch kind {
	case "pipeline":
		_, err = c.IssuePipeline(ctx, connect.NewRequest(&didpb.IssuePipelineRequest{
			TargetDid: targetDID, Delegation: dlgBytes, ExternalPublicKeys: extpb,
		}))
	case "process":
		_, err = c.IssueProcess(ctx, connect.NewRequest(&didpb.IssueProcessRequest{
			TargetDid: targetDID, Delegation: dlgBytes, ExternalPublicKeys: extpb,
		}))
	default:
		return fmt.Errorf("issue: unknown kind %q", kind)
	}
	if err != nil {
		return fmt.Errorf("%s create: issue %s: %w", kind, targetDID, err)
	}
	if external != nil {
		fmt.Fprintf(env.out(), "issued %s %s (external key: signing keys held locally, never by the registry)\n", kind, targetDID)
	} else {
		fmt.Fprintf(env.out(), "issued %s %s (signing keys held by the registry)\n", kind, targetDID)
	}
	return nil
}
