/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package auth_test

import (
	"sort"
	"strings"
	"testing"

	policy "github.com/o3co/protobuf.interceptors/schema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	// Blank-import every dplaax service so its file descriptor registers in
	// protoregistry.GlobalFiles; the walk below is only authoritative if they
	// are all present. The wantServices set below is asserted exactly, so a
	// DROPPED import (walk misses a service) or a NEW service reachable in the
	// registry but absent from the set both FAIL the test — the import list
	// cannot silently drift out of sync with the real service surface.
	_ "github.com/provin-line/oss/gen/go/dplaax/audit/v1"
	_ "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	_ "github.com/provin-line/oss/gen/go/dplaax/did/v1"
	_ "github.com/provin-line/oss/gen/go/dplaax/payload/v1"
	_ "github.com/provin-line/oss/gen/go/dplaax/schema/v1"
	_ "github.com/provin-line/oss/gen/go/dplaax/signer/v1"
	_ "github.com/provin-line/oss/gen/go/dplaax/tlog/v1"
	_ "github.com/provin-line/oss/gen/go/dplaax/vc/v1"
)

// l2Exempt lists the fully-qualified services that legitimately carry NO L1
// policy option because they authenticate at L2 (per-RPC wireauth), not through
// the PDP. Every OTHER method of every dplaax service must be annotated, or it
// would be served unauthenticated (the o3co interceptor treats "no policy" as
// pass-through). Keyed by FULL name so a same-named service in another package
// cannot silently satisfy the exemption.
var l2Exempt = map[protoreflect.FullName]bool{
	"dplaax.chain.v1.ChainPeerService": true,
	"dplaax.payload.v1.PayloadService": true,
}

// wantServices is the exact set of dplaax services the walk must find. Pinning
// it (rather than a bare "services > 0") is what makes the walk authoritative:
// a dropped blank import above shrinks the found set and fails here, and a new
// service must be added to BOTH the imports and this set — so the guard cannot
// silently miss a surface.
var wantServices = map[protoreflect.FullName]bool{
	"dplaax.schema.v1.SchemaService":   true,
	"dplaax.did.v1.DIDService":         true,
	"dplaax.signer.v1.SignerService":   true,
	"dplaax.vc.v1.VCResolverService":   true,
	"dplaax.audit.v1.AuditService":     true,
	"dplaax.tlog.v1.TlogService":       true,
	"dplaax.chain.v1.ChainService":     true,
	"dplaax.chain.v1.ChainPeerService": true,
	"dplaax.payload.v1.PayloadService": true,
}

// TestEveryRPCIsGuarded walks the ACTUAL registered service descriptors — not a
// hand-maintained list — and fails if any method of a non-exempt dplaax service
// lacks a valid policy option. This closes the fail-open gap the snapshot test
// leaves: an unannotated RPC would appear in neither the snapshot's got nor
// want and pass, yet ship open.
func TestEveryRPCIsGuarded(t *testing.T) {
	var unguarded []string
	found := map[protoreflect.FullName]bool{}
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if !strings.HasPrefix(string(fd.Package()), "dplaax.") {
			return true
		}
		svcs := fd.Services()
		for i := 0; i < svcs.Len(); i++ {
			svc := svcs.Get(i)
			found[svc.FullName()] = true
			if l2Exempt[svc.FullName()] {
				continue
			}
			methods := svc.Methods()
			for j := 0; j < methods.Len(); j++ {
				m := methods.Get(j)
				opts := m.Options()
				if !proto.HasExtension(opts, policy.E_Policy) {
					unguarded = append(unguarded, string(m.FullName())+" (no policy option)")
					continue
				}
				p, ok := proto.GetExtension(opts, policy.E_Policy).(*policy.Policy)
				if !ok || p.GetResource() == "" || p.GetAction() == "" {
					unguarded = append(unguarded, string(m.FullName())+" (empty resource/action)")
				}
			}
		}
		return true
	})

	// The found set must EXACTLY equal the expected set: a missing/dropped
	// blank import (found < want) or a new service not yet accounted for
	// (found > want) both fail here, so the walk can never silently miss a
	// surface.
	for name := range wantServices {
		if !found[name] {
			t.Errorf("expected dplaax service %q not registered — its blank import is missing, so the walk skips it", name)
		}
	}
	for name := range found {
		if !wantServices[name] {
			t.Errorf("dplaax service %q is registered but not in wantServices — add it here and confirm it is guarded (or exempt)", name)
		}
	}
	if len(unguarded) > 0 {
		sort.Strings(unguarded)
		t.Errorf("methods served WITHOUT an L1 policy option (would ship unauthenticated):\n  %s\n"+
			"-> annotate the RPC with (o3co.authz.v1.policy), or add its service to l2Exempt if it is L2-authenticated",
			strings.Join(unguarded, "\n  "))
	}
}

// TestL2ExemptionsAreLoadBearing proves the exemption list is not vacuous: with
// it removed, the L2 services WOULD be flagged (they carry no policy option).
// This keeps the exemption honest — a stale entry cannot silently hide a
// genuinely unguarded surface.
func TestL2ExemptionsAreLoadBearing(t *testing.T) {
	for name := range l2Exempt {
		desc, err := protoregistry.GlobalFiles.FindDescriptorByName(name)
		if err != nil {
			t.Errorf("exempt service %q not found in registry: %v", name, err)
			continue
		}
		svc, ok := desc.(protoreflect.ServiceDescriptor)
		if !ok {
			t.Errorf("%q is not a service descriptor", name)
			continue
		}
		methods := svc.Methods()
		for j := 0; j < methods.Len(); j++ {
			if proto.HasExtension(methods.Get(j).Options(), policy.E_Policy) {
				t.Errorf("%s carries a policy option — it is L1-guarded, so it should NOT be in l2Exempt", methods.Get(j).FullName())
			}
		}
	}
}
