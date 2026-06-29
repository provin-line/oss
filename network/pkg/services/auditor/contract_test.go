package auditor_test

import (
	"testing"

	policy "github.com/o3co/protobuf.interceptors/schema"
	"google.golang.org/protobuf/proto"

	auditpb "github.com/provin-line/oss/gen/go/dplaax/audit/v1"
)

// Fail-open guard: every AuditService RPC must carry the o3co.authz.v1.policy option,
// with the exact frozen resource/action values (D-17i-1). A missing option silently
// disables the authorization check; a typo/swap would mis-route authorization while
// passing a presence-only check. The wire-visible contract is frozen the moment
// audit.proto is written (slice-17i Phase A), before any handler exists.
func TestAuditService_RPCPolicies(t *testing.T) {
	want := map[string]struct{ resource, action string }{
		"GetAuditStatus": {"audit", "read"},
	}
	methods := auditpb.File_dplaax_audit_v1_audit_proto.Services().ByName("AuditService").Methods()
	if methods.Len() != len(want) {
		t.Fatalf("AuditService has %d methods, want %d", methods.Len(), len(want))
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
