package payloadresolver_test

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	policy "github.com/o3co/protobuf.interceptors/schema"
	payloadpb "github.com/provin-line/oss/gen/go/dplaax/payload/v1"
)

// PayloadService is the internet-facing L2 surface (wireauth), mirroring
// dplaax.chain.v1.ChainPeerService:
//   - NO RPC carries the o3co.authz.v1.policy option (it is L2-gated by wireauth,
//     not by the L1 interceptor);
//   - every request message carries an auth_proof field of type AuthProof — the
//     proof its handler must verify can never be omitted from the wire.
// Both directions are asserted as a descriptor contract.

// TestPayloadService_NoL1Policy asserts no RPC carries the L1 policy option.
func TestPayloadService_NoL1Policy(t *testing.T) {
	methods := payloadpb.File_dplaax_payload_v1_payload_proto.Services().ByName("PayloadService").Methods()
	if methods.Len() == 0 {
		t.Fatal("PayloadService has no methods")
	}
	for i := 0; i < methods.Len(); i++ {
		m := methods.Get(i)
		if proto.HasExtension(m.Options(), policy.E_Policy) {
			t.Errorf("RPC %s carries the o3co.authz.v1.policy option, but PayloadService is L2-only (wireauth), not L1-gated", m.Name())
		}
	}
}

// TestPayloadService_RequestsCarryAuthProof asserts the positive L2 contract.
func TestPayloadService_RequestsCarryAuthProof(t *testing.T) {
	methods := payloadpb.File_dplaax_payload_v1_payload_proto.Services().ByName("PayloadService").Methods()
	if methods.Len() == 0 {
		t.Fatal("PayloadService has no methods")
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
	return ""
}
