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
// written (slice-5 Phase A), before any handler exists.
//
// Beyond presence, the exact resource/action values are asserted: D-s2 freezes
// `signer:sign-vc` / `signer:sign-wire` as wire-visible names, and a typo or a
// swap between the two domains would silently mis-route authorization while
// still passing a presence-only check.
func TestSignerService_RPCPolicies(t *testing.T) {
	want := map[string]struct{ resource, action string }{
		"Sign":    {"signer", "sign-vc"},
		"SignRaw": {"signer", "sign-wire"},
	}
	methods := signerpb.File_dplaax_signer_v1_signer_proto.Services().ByName("SignerService").Methods()
	if methods.Len() != len(want) {
		t.Fatalf("SignerService has %d methods, want %d", methods.Len(), len(want))
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
