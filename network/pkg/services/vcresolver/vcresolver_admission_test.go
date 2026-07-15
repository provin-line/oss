package vcresolver_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
)

// StoreVC is a body-as-SoT admission boundary: unknown members survive into
// the stored canonical bytes. An externally-received credential carrying an
// integer outside ±(2^53-1) would be silently ROUNDED by the RFC 8785
// re-serialization on store — the stored bytes would no longer be the received
// bytes, and any signature over the original would never verify again. The
// admission gate turns that silent corruption into a loud rejection
// (canon.number.safe-integer: a new artifact's integers are gated at the
// boundary, before anything durable happens).
func TestStoreVC_RejectsUnsafeIntegerInsteadOfRoundingAtRest(t *testing.T) {
	svc := vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), memstore.NewPool())

	wire := `{
		"@context": ["https://www.w3.org/ns/credentials/v2", "https://dplaax.dev/vc/v1", "https://provin.dev/vc/v1"],
		"type": ["VerifiableCredential", "PipelinePassCredential"],
		"issuer": "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:proc1",
		"credentialSubject": {"pipelineId": "p1", "extCounter": 9007199254740993}
	}`
	_, err := svc.StoreVC(context.Background(), []byte(wire), "", 0)
	if err == nil {
		t.Fatal("StoreVC admitted a credential whose bytes it would silently rewrite")
	}
	if !strings.Contains(err.Error(), "unsafe number") {
		t.Errorf("error does not name the unsafe number: %v", err)
	}

	// The same credential with the counter in the string domain is admissible.
	var m map[string]any
	if err := json.Unmarshal([]byte(wire), &m); err != nil {
		t.Fatal(err)
	}
	m["credentialSubject"].(map[string]any)["extCounter"] = "9007199254740993"
	safe, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StoreVC(context.Background(), safe, "", 0); err != nil {
		t.Errorf("StoreVC rejected the string-domain form: %v", err)
	}
}
