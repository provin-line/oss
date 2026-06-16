package signer

import (
	"testing"

	policy "github.com/o3co/protobuf.interceptors/schema"
	"google.golang.org/protobuf/proto"

	signerpb "github.com/provin-line/oss/gen/go/dplaax/signer/v1"
)

// Fail-open guard: every SignerService RPC must carry the o3co.authz.v1.policy
// option. A missing option silently disables the authorization check, so this
// catches an accidentally-unprotected signing RPC at build time — the
// wire-visible authorization contract is frozen the moment signer.proto is
// written (slice-5 Phase A), before any handler exists. Mirrors
// didregistry/contract_test.go.
func TestSignerService_AllRPCsAnnotated(t *testing.T) {
	methods := signerpb.File_dplaax_signer_v1_signer_proto.Services().ByName("SignerService").Methods()
	if methods.Len() != 2 {
		t.Fatalf("SignerService has %d methods, want 2", methods.Len())
	}
	for i := 0; i < methods.Len(); i++ {
		m := methods.Get(i)
		if !proto.HasExtension(m.Options(), policy.E_Policy) {
			t.Errorf("RPC %s is missing the o3co.authz.v1.policy option (would be unprotected)", m.Name())
		}
	}
}
