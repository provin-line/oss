package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/cmd/provin/internal/keyfile"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	didpb "github.com/provin-line/oss/gen/go/dplaax/did/v1"
	"github.com/provin-line/oss/gen/go/dplaax/did/v1/didpbconnect"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/vc"
)

// OwnerInit establishes a pipeline owner: it ensures a CLI-local owner key at
// keyPath (generating one if absent — the only private key that ever exists
// outside the registry), builds the owner's self-signed DID document, and
// registers it via RegisterOwner.
//
// Ordering is custody-first: the key is on disk before the registry learns
// the DID, so a failure between the two steps is retryable — a re-run finds
// and reuses the existing key file (its kid must match ownerDID; a mismatch
// is a hard error, never a silent mis-registration).
func OwnerInit(ctx context.Context, env Env, ownerDID, keyPath string) error {
	key, err := ensureKey(keyPath, ownerDID)
	if err != nil {
		return err
	}
	docBytes, err := selfSignedOwnerDoc(key)
	if err != nil {
		return err
	}
	c, err := env.didClient()
	if err != nil {
		return err
	}
	if _, err := c.RegisterOwner(ctx, connect.NewRequest(&didpb.RegisterOwnerRequest{
		DidDocument: docBytes,
	})); err != nil {
		// AlreadyExists is not necessarily a failure: each run signs a fresh
		// proof (new timestamp), so the registry's exact-bytes idempotency
		// rejects a retry AFTER a success that this client never saw. Resolve
		// the registered document and compare keys instead of guessing.
		if connect.CodeOf(err) == connect.CodeAlreadyExists {
			return confirmRegisteredKey(ctx, c, env, key, keyPath)
		}
		return fmt.Errorf("owner init: RegisterOwner(%s): %w (owner key kept at %s; re-run to retry)", ownerDID, err, keyPath)
	}
	fmt.Fprintf(env.out(), "registered owner %s (key: %s)\n", ownerDID, keyPath)
	return nil
}

// confirmRegisteredKey settles an AlreadyExists registration: if the DID's
// registered #signing key IS this key file's public key, the owner is already
// established and the command succeeds idempotently; a different key means
// this key file cannot act for the DID — an honest hard error, not a retry
// suggestion.
func confirmRegisteredKey(ctx context.Context, c didpbconnect.DIDServiceClient, env Env, key *keyfile.Key, keyPath string) error {
	res, err := c.ResolveDID(ctx, connect.NewRequest(&didpb.ResolveDIDRequest{Did: key.DID}))
	if err != nil {
		return fmt.Errorf("owner init: %s is already registered but resolving it to compare keys failed: %w", key.DID, err)
	}
	var doc did.DIDDocument
	if err := canon.NewStrictDecoder(res.Msg.GetDidDocument()).Decode(&doc); err != nil {
		return fmt.Errorf("owner init: parse registered document for %s: %w", key.DID, err)
	}
	// Compare raw key bytes, not one encoding's rendering of them: the same key
	// is the same key whether the registered document carries it as Multikey or
	// as a legacy JWK, and a comparison pinned to publicKeyJwk["x"] would report
	// a Multikey-registered owner as a DIFFERENT key on every re-run.
	registered, _, err := did.ExtractPublicKeyAndEncoding(&doc, key.DID+"#signing", did.RelationshipAssertionMethod)
	if err != nil {
		return fmt.Errorf("owner init: %s is already registered but its #signing key is unreadable: %v — the file at %s cannot be confirmed against it", key.DID, err, keyPath)
	}
	if bytes.Equal(registered, key.PublicKey) {
		fmt.Fprintf(env.out(), "owner %s already registered with this key; nothing to do (key: %s)\n", key.DID, keyPath)
		return nil
	}
	return fmt.Errorf("owner init: %s is registered under a DIFFERENT key — the file at %s cannot act for this DID (locate the original key file, or register a new DID)", key.DID, keyPath)
}

// ensureKey loads the owner key at path, or generates and persists a fresh
// one when the file does not exist.
func ensureKey(path, ownerDID string) (*keyfile.Key, error) {
	if _, err := os.Stat(path); err == nil {
		key, err := keyfile.Load(path)
		if err != nil {
			return nil, fmt.Errorf("%w (if this file is a leftover of a failed init that never registered, delete it and re-run)", err)
		}
		if key.DID != ownerDID {
			return nil, fmt.Errorf("owner init: key file %s holds %s, not %s — refusing to register under a different identity (pass a different --key path)", path, key.DID, ownerDID)
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("owner init: stat %s: %w", path, err)
	}
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		return nil, fmt.Errorf("owner init: keygen: %w", err)
	}
	if err := keyfile.Write(path, ownerDID, kp.PublicKey, kp.PrivateKey); err != nil {
		return nil, err
	}
	return &keyfile.Key{DID: ownerDID, PublicKey: kp.PublicKey, PrivateKey: kp.PrivateKey}, nil
}

// selfSignedOwnerDoc builds the owner's self-signed DID document registration
// body: a document whose #signing verification method is the owner's own key,
// proved with an EdDSA-JCS-2022 data-integrity proof by that same key (the
// registration bootstrap — there is no prior authority to sign under).
func selfSignedOwnerDoc(key *keyfile.Key) ([]byte, error) {
	// Multikey, not JWK: the W3C eddsa-jcs-2022 suite requires it, and the proof
	// this document carries is W3C-shaped (signer.suite.eddsa-jcs-2022).
	vm, err := did.NewMultikeyVerificationMethod(key.DID+"#signing", key.DID, key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("encode owner signing key: %w", err)
	}
	base := did.New(did.DocumentFields{
		// The @context is load-bearing: the W3C proof shape mirrors it onto the
		// proof, and the suite classifier requires that mirror (a context-free
		// document would self-sign into a proof matching no claim contract).
		Context: did.IssuedDocumentContexts(),
		ID:      key.DID, Controller: key.DID,
		VerificationMethod: []did.VerificationMethod{vm},
		AssertionMethod:    []string{key.DID + "#signing"},
	})
	body := base.Body()
	proof, err := vc.CreateProof(key.Signer(), key.DID, string(keystore.KeyIDSigning), key.DID+"#signing", body, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		return nil, fmt.Errorf("owner init: sign owner document: %w", err)
	}
	// Not a signing scope: the proof was computed inside vc.CreateProof over
	// the JCS-canonical body; this marshal only reshapes the struct into the
	// document map, and the registry re-canonicalizes to verify
	// (canonicalizer-hygiene-exempt).
	pb, err := json.Marshal(proof)
	if err != nil {
		return nil, fmt.Errorf("owner init: marshal proof: %w", err)
	}
	var pm map[string]any
	// Reshaping a proof this process just marshaled itself — no untrusted
	// bytes, no duplicate-key vector (decoder-hygiene-exempt).
	if err := json.Unmarshal(pb, &pm); err != nil {
		return nil, fmt.Errorf("owner init: reshape proof: %w", err)
	}
	body["proof"] = pm
	// Wire encoding only, not a signing scope: the registry JCS-canonicalizes
	// the received document itself for hashing and proof verification
	// (canonicalizer-hygiene-exempt).
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("owner init: marshal owner document: %w", err)
	}
	return raw, nil
}
