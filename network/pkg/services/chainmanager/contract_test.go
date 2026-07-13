package chainmanager

import (
	"testing"

	policy "github.com/o3co/protobuf.interceptors/schema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
)

// The chain control plane is split across two services with opposite
// authorization models, and that split is a wire-visible contract frozen the
// moment chain.proto is written (slice-9 Phase A), before any handler exists.
// These guards assert the split in BOTH directions so neither half can silently
// drift into the other (slice-9 D-c1):
//
//   - ChainService (operator, L1 JWT): every RPC carries the o3co.authz.v1.policy
//     option. A missing option silently disables the authorization check.
//   - ChainPeerService (internet, L2 wireauth): NO RPC carries the policy option
//     (the network auth layer treats an option-less RPC as "not L1-gated"), AND
//     every request message carries an auth_proof field of type AuthProof — the
//     positive half of the L2 contract. Absence-of-option alone would not stop a
//     future peer RPC shipping with no proof field at all, leaving a handler that
//     forgets to verify with nothing to verify against.

// TestChainService_RPCPolicies asserts every ChainService RPC carries the
// expected o3co policy option (presence + exact resource/action).
func TestChainService_RPCPolicies(t *testing.T) {
	want := map[string]struct{ resource, action string }{
		"Subscribe":         {"chain", "subscribe"},
		"Unsubscribe":       {"chain", "unsubscribe"},
		"ListSubscriptions": {"chain", "read"},
		"UpdateAllowList":   {"chain", "update-allowlist"},
		"GetAllowList":      {"chain", "read-allowlist"},
	}
	methods := chainpb.File_dplaax_chain_v1_chain_proto.Services().ByName("ChainService").Methods()
	if methods.Len() != len(want) {
		t.Fatalf("ChainService has %d methods, want %d", methods.Len(), len(want))
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

// TestChainPeerService_NoL1Policy asserts no ChainPeerService RPC carries the L1
// policy option — these are L2-gated by wireauth, not by the L1 interceptor.
func TestChainPeerService_NoL1Policy(t *testing.T) {
	methods := chainpb.File_dplaax_chain_v1_chain_proto.Services().ByName("ChainPeerService").Methods()
	if methods.Len() == 0 {
		t.Fatal("ChainPeerService has no methods")
	}
	for i := 0; i < methods.Len(); i++ {
		m := methods.Get(i)
		if proto.HasExtension(m.Options(), policy.E_Policy) {
			t.Errorf("RPC %s carries the o3co.authz.v1.policy option, but ChainPeerService is L2-only (wireauth), not L1-gated", m.Name())
		}
	}
}

// TestChainPeerService_RequestsCarryAuthProof asserts the positive L2 contract:
// every ChainPeerService request message has an auth_proof field of type
// AuthProof, so a peer RPC can never ship without the proof its handler must
// verify.
func TestChainPeerService_RequestsCarryAuthProof(t *testing.T) {
	methods := chainpb.File_dplaax_chain_v1_chain_proto.Services().ByName("ChainPeerService").Methods()
	if methods.Len() == 0 {
		t.Fatal("ChainPeerService has no methods")
	}
	for i := 0; i < methods.Len(); i++ {
		m := methods.Get(i)
		in := m.Input()
		f := in.Fields().ByName("auth_proof")
		if f == nil {
			t.Errorf("RPC %s: request %s has no auth_proof field (L2 proof contract)", m.Name(), in.Name())
			continue
		}
		if f.Kind() != protoreflect.MessageKind || f.Message().Name() != "AuthProof" {
			t.Errorf("RPC %s: auth_proof field is %v/%s, want message/AuthProof", m.Name(), f.Kind(), messageName(f))
		}
	}
}

func messageName(f protoreflect.FieldDescriptor) protoreflect.Name {
	if f.Kind() == protoreflect.MessageKind {
		return f.Message().Name()
	}
	return protoreflect.Name("<not a message>")
}
