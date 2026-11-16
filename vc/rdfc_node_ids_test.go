package vc_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

const (
	nodeIDSchema    = "dplaax:schema/nodes@1.0.0"
	nodeIDSchemaIRI = "https://dplaax.dev/vocab#schema/nodes@1.0.0"
)

// nodeIDBody is the body of a first credential with a schema, as vc writes it,
// holding no id on any node object.
func nodeIDBody(t *testing.T) map[string]any {
	t.Helper()
	cred, err := vc.New(vc.CredentialFields{
		Issuer:    procAOrigin,
		ValidFrom: time.Date(2026, 7, 13, 9, 0, 0, 0, time.UTC),
		Subject: vc.CredentialSubjectFields{
			PipelineID: "p1", ProcessID: "procA", TransformationClaim: vc.ClaimConvert,
			Schema:    vc.SchemaRef{ID: nodeIDSchema, Type: "JsonSchema", ContentHash: "sha256:" + repeatHex("5a")},
			InputHash: "sha256:" + repeatHex("22"), OutputHash: "sha256:" + repeatHex("33"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return cred.Body()
}

// nodeIDs sets the ids of the credential, its subject and its schema; an
// empty id leaves the credential or subject without one and the schema with
// the id it has, as a schema always carries one.
type nodeIDs struct{ root, subject, schema string }

func (n nodeIDs) apply(body map[string]any) {
	subject := body["credentialSubject"].(map[string]any)
	schema := subject["schema"].(map[string]any)
	set := func(obj map[string]any, id string) {
		if id == "" {
			delete(obj, "id")
			return
		}
		obj["id"] = id
	}
	set(body, n.root)
	set(subject, n.subject)
	if n.schema != "" {
		schema["id"] = n.schema
	}
}

// signedBody signs body as procAOrigin under suite and returns the credential
// it forms, the proof's public key and a resolver for the issuer.
func signedBody(t *testing.T, body map[string]any, suite string) (*vc.PipelinePassCredential, []byte, *vc.DataIntegrityProof, *local.Resolver) {
	t.Helper()
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	ks := newMemKeyStore()
	if err := ks.SaveKeyPair(procAOrigin, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
		t.Fatal(err)
	}
	proof, err := vc.CreateProof(ks, procAOrigin, string(keystore.KeyIDSigning), procAOrigin+"#signing", body, suite)
	if err != nil {
		t.Fatal(err)
	}
	r := local.New()
	r.Add(didDoc(procAOrigin, ownerOf(t, procAOrigin), procAOrigin+"#signing", kp.PublicKey))
	r.Add(didDoc(ownerOf(t, procAOrigin), ownerOf(t, procAOrigin), "", nil))
	return withProof(t, body, proof), kp.PublicKey, proof, r
}

// withProof is the credential of body carrying proof.
func withProof(t *testing.T, body map[string]any, proof *vc.DataIntegrityProof) *vc.PipelinePassCredential {
	t.Helper()
	wire := map[string]any{}
	for k, v := range body {
		wire[k] = v
	}
	p, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	var pm map[string]any
	if err := json.Unmarshal(p, &pm); err != nil {
		t.Fatal(err)
	}
	wire["proof"] = pm
	b, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	var c vc.PipelinePassCredential
	if err := c.UnmarshalJSON(b); err != nil {
		t.Fatal(err)
	}
	return &c
}

// Moving a type between the credential and its schema, when both name one
// node, leaves the signature valid and changes what Subject().Schema.Type
// reads; the closed form refuses the credential.
func TestRDFCCredential_MovingTypeBetweenNodesOfOneIDIsRefused(t *testing.T) {
	signedForm := nodeIDBody(t)
	nodeIDs{root: nodeIDSchema, schema: nodeIDSchema}.apply(signedForm)
	signedForm["type"] = append(signedForm["type"].([]any), "JsonSchemaCredential")
	genuine, pub, proof, r := signedBody(t, signedForm, vc.CryptosuiteEdDSARDFC2022)

	moved := nodeIDBody(t)
	nodeIDs{root: nodeIDSchema, schema: nodeIDSchema}.apply(moved)
	moved["type"] = append(moved["type"].([]any), "JsonSchema")
	moved["credentialSubject"].(map[string]any)["schema"].(map[string]any)["type"] = "JsonSchemaCredential"

	if err := vc.VerifyProof(ed25519.Verifier{}, pub, proof, moved); err != nil {
		t.Fatalf("the signature does not cover the moved form: %v", err)
	}
	bent := withProof(t, moved, proof)
	was, _ := genuine.Subject()
	now, _ := bent.Subject()
	if was.Schema.Type == now.Schema.Type {
		t.Fatalf("Subject().Schema.Type is %q in both forms", was.Schema.Type)
	}
	if err := bent.ValidateWireForm(); err == nil {
		t.Errorf("ValidateWireForm accepted a credential whose Subject().Schema.Type reads %q, signed as %q", now.Schema.Type, was.Schema.Type)
	}
	res, err := vc.NewVerifier(r, ed25519Verifier()).Verify(context.Background(), bent)
	if err != nil {
		t.Fatal(err)
	}
	if res.Axes.DataIntegrity != vc.ConfidenceFailed {
		t.Errorf("data integrity %v, want Failed", res.Axes.DataIntegrity)
	}
}

// An eddsa-rdfc-2022 credential in which two node objects name one node,
// however each writes the id, is refused wherever the closed form is held; one
// whose ids are distinct is accepted.
func TestRDFCCredential_NodeObjectsCarryDistinctIDs(t *testing.T) {
	const (
		rootFull   = "https://example.org/credential/1"
		subjectDID = "did:example:subject"
	)
	cases := []struct {
		name    string
		ids     nodeIDs
		refused bool
	}{
		{"a schema id alone", nodeIDs{}, false},
		{"three distinct ids", nodeIDs{rootFull, subjectDID, nodeIDSchema}, false},
		{"a root id alone", nodeIDs{root: rootFull}, false},
		{"a compact and a full IRI that differ", nodeIDs{root: "dplaax:schema/other@1.0.0", schema: nodeIDSchemaIRI}, false},
		{"root and schema, the same string", nodeIDs{root: nodeIDSchema, schema: nodeIDSchema}, true},
		{"root and subject, the same string", nodeIDs{root: rootFull, subject: rootFull, schema: nodeIDSchema}, true},
		{"subject and schema, the same string", nodeIDs{root: rootFull, subject: nodeIDSchema, schema: nodeIDSchema}, true},
		{"all three, the same string", nodeIDs{rootFull, rootFull, rootFull}, true},
		{"root and schema, compact and full", nodeIDs{root: nodeIDSchema, schema: nodeIDSchemaIRI}, true},
		{"root and schema, full and compact", nodeIDs{root: nodeIDSchemaIRI, schema: nodeIDSchema}, true},
		{"root and subject, compact and full", nodeIDs{root: "dplaax:node", subject: "https://dplaax.dev/vocab#node", schema: nodeIDSchema}, true},
		{"subject and schema, compact and full", nodeIDs{root: rootFull, subject: "dplaax:schema/nodes@1.0.0", schema: nodeIDSchemaIRI}, true},
		{"root and subject, two prefixes of one IRI", nodeIDs{root: "provin:node", subject: "https://provin.dev/vocab#node", schema: nodeIDSchema}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := nodeIDBody(t)
			tc.ids.apply(body)
			cred, _, _, r := signedBody(t, body, vc.CryptosuiteEdDSARDFC2022)
			wire := cred.ValidateWireForm()
			var linkErr *vc.ChainLinkError
			links := vc.ValidateChainLinks([]*vc.PipelinePassCredential{cred})
			if tc.refused {
				if wire == nil {
					t.Error("ValidateWireForm accepted it")
				}
				if !errors.As(links, &linkErr) || linkErr.Index != 0 {
					t.Errorf("ValidateChainLinks = %v, want a *ChainLinkError at 0", links)
				}
				res, err := vc.NewVerifier(r, ed25519Verifier()).Verify(context.Background(), cred)
				if err != nil {
					t.Fatal(err)
				}
				if res.Axes.DataIntegrity != vc.ConfidenceFailed {
					t.Errorf("data integrity %v, want Failed", res.Axes.DataIntegrity)
				}
				return
			}
			if wire != nil {
				t.Errorf("ValidateWireForm: %v", wire)
			}
			if links != nil {
				t.Errorf("ValidateChainLinks: %v", links)
			}
		})
	}
}

// An eddsa-jcs-2022 credential whose node objects share an id is accepted as
// before: the closed form applies to eddsa-rdfc-2022 only.
func TestJCSCredential_NodeObjectsMayShareAnID(t *testing.T) {
	body := nodeIDBody(t)
	nodeIDs{root: nodeIDSchema, subject: nodeIDSchema, schema: nodeIDSchemaIRI}.apply(body)
	cred, _, _, _ := signedBody(t, body, vc.CryptosuiteEdDSAJCS2022)
	if err := cred.ValidateWireForm(); err != nil {
		t.Errorf("ValidateWireForm: %v", err)
	}
	if err := vc.ValidateChainLinks([]*vc.PipelinePassCredential{cred}); err != nil {
		t.Errorf("ValidateChainLinks: %v", err)
	}
}
