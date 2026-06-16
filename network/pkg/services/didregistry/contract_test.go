package didregistry

import (
	"testing"

	policy "github.com/o3co/protobuf.interceptors/schema"
	"google.golang.org/protobuf/proto"

	didpb "github.com/provin-line/oss/gen/go/dplaax/did/v1"
)

// Fail-open guard: every DIDService RPC must carry the o3co.authz.v1.policy
// option. A missing option silently disables the authorization check, so this
// catches an accidentally-unprotected RPC at build time — the wire-visible
// authorization contract is frozen the moment did.proto is written (slice-4
// Phase 1), before any handler exists.
func TestDIDService_AllRPCsAnnotated(t *testing.T) {
	methods := didpb.File_dplaax_did_v1_did_proto.Services().ByName("DIDService").Methods()
	if methods.Len() != 9 {
		t.Fatalf("DIDService has %d methods, want 9", methods.Len())
	}
	for i := 0; i < methods.Len(); i++ {
		m := methods.Get(i)
		if !proto.HasExtension(m.Options(), policy.E_Policy) {
			t.Errorf("RPC %s is missing the o3co.authz.v1.policy option (would be unprotected)", m.Name())
		}
	}
}
