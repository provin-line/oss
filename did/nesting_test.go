package did_test

import (
	"encoding/json"
	"reflect"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/provin-line/oss/did"
)

func deepValue(depth int) any {
	var v any = "x"
	for i := range depth {
		if i%2 == 0 {
			v = []any{v}
		} else {
			v = map[string]any{"k": v}
		}
	}
	return v
}

// A verification method's publicKeyJwk built in Go a million deep is copied
// without recursing (held to a 64 MB stack, a recursive copy would exhaust
// it, a fatal error): New and Body return, and Hash refuses the nesting.
func TestNew_CopiesADeepPublicKeyJWKWithoutRecursing(t *testing.T) {
	defer debug.SetMaxStack(debug.SetMaxStack(64 << 20))
	doc := did.New(did.DocumentFields{
		ID: "did:dplaax:poc.dplaax.dev:org:acme",
		VerificationMethod: []did.VerificationMethod{{
			ID:           "did:dplaax:poc.dplaax.dev:org:acme#k",
			Type:         "JsonWebKey2020",
			Controller:   "did:dplaax:poc.dplaax.dev:org:acme",
			PublicKeyJWK: map[string]any{"kty": "OKP", "deep": deepValue(1000000)},
		}},
	})
	if body := doc.Body(); body == nil {
		t.Fatal("Body: nil")
	}
	if _, err := doc.Hash(); err == nil || !strings.Contains(err.Error(), "nested deeper than") {
		t.Errorf("Hash: %v, want the nesting refused", err)
	}
}

// The copy New and Body make of a publicKeyJwk equals it, scalars of every
// kind and empty containers included, and shares no map or slice with it:
// changing the copy leaves the caller's value as it was.
func TestNew_CopiesAPublicKeyJWKWhole(t *testing.T) {
	jwk := map[string]any{"kty": "OKP", "crv": "Ed25519"}
	node := jwk
	for i := range 50 {
		next := map[string]any{"n": json.Number("1"), "b": i%2 == 0, "z": nil, "e": map[string]any{}, "a": []any{}, "s": []any{"x", map[string]any{"y": "v"}}}
		node["next"] = next
		node = next
	}
	want, err := json.Marshal(jwk)
	if err != nil {
		t.Fatal(err)
	}
	doc := did.New(did.DocumentFields{
		ID: "did:dplaax:poc.dplaax.dev:org:acme",
		VerificationMethod: []did.VerificationMethod{{
			ID: "did:dplaax:poc.dplaax.dev:org:acme#k", Type: "JsonWebKey2020", Controller: "did:dplaax:poc.dplaax.dev:org:acme", PublicKeyJWK: jwk,
		}},
	})
	vms, _ := doc.Body()["verificationMethod"].([]any)
	if len(vms) != 1 {
		t.Fatalf("verificationMethod: %v", doc.Body()["verificationMethod"])
	}
	got := vms[0].(map[string]any)["publicKeyJwk"].(map[string]any)
	if !reflect.DeepEqual(got, jwk) {
		t.Fatal("the copy differs from the publicKeyJwk")
	}
	for copied := got; copied != nil; {
		copied["changed"] = true
		next, _ := copied["next"].(map[string]any)
		if next != nil {
			next["s"].([]any)[0] = "changed"
		}
		copied = next
	}
	if after, _ := json.Marshal(jwk); string(after) != string(want) {
		t.Error("changing the copy changed the caller's publicKeyJwk")
	}
}
