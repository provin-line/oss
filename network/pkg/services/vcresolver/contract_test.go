package vcresolver

import (
	"testing"

	policy "github.com/o3co/protobuf.interceptors/schema"
	"google.golang.org/protobuf/proto"

	vcpb "github.com/provin-line/oss/gen/go/dplaax/vc/v1"
)

// Fail-open guard: every VCResolverService RPC must carry the o3co.authz.v1.policy
// option, with the exact frozen resource/action values (D-v2). A missing option
// silently disables the authorization check; a typo/swap would mis-route
// authorization while passing a presence-only check. The wire-visible contract is
// frozen the moment vc.proto is written (slice-7 Phase A), before any handler exists.
func TestVCResolverService_RPCPolicies(t *testing.T) {
	want := map[string]struct{ resource, action string }{
		"StoreVC":        {"vc", "store"},
		"ResolveVC":      {"vc", "read"},
		"ListSuccessors": {"vc", "read"},
		// Variant reads are the same exposure class as a VC read — which
		// signed forms a body has, and their bytes, is provenance topology,
		// not an open identity document. Same gate, deliberately.
		"ResolveVariant": {"vc", "read"},
		"ListVariants":   {"vc", "read"},
	}
	methods := vcpb.File_dplaax_vc_v1_vc_proto.Services().ByName("VCResolverService").Methods()
	if methods.Len() != len(want) {
		t.Fatalf("VCResolverService has %d methods, want %d", methods.Len(), len(want))
	}
	for i := 0; i < methods.Len(); i++ {
		m := methods.Get(i)
		name := string(m.Name())
		if !proto.HasExtension(m.Options(), policy.E_Policy) {
			t.Errorf("RPC %s is missing the o3co.authz.v1.policy option (would be unprotected)", name)
			continue
		}
		w, ok := want[name]
		if !ok {
			t.Errorf("unexpected RPC %s", name)
			continue
		}
		p, ok := proto.GetExtension(m.Options(), policy.E_Policy).(*policy.Policy)
		if !ok || p == nil {
			t.Errorf("RPC %s: policy extension has unexpected type", name)
			continue
		}
		if p.GetResource() != w.resource || p.GetAction() != w.action {
			t.Errorf("RPC %s: policy = {resource:%q action:%q}, want {resource:%q action:%q}",
				name, p.GetResource(), p.GetAction(), w.resource, w.action)
		}
	}
}
